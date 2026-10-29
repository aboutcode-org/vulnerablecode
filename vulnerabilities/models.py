#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime
import logging
import uuid
from contextlib import suppress
from functools import cached_property
from inspect import cleandoc
from traceback import format_exc as traceback_format_exc
from typing import Dict
from typing import List
from typing import NamedTuple
from typing import Optional
from typing import Set
from typing import Union
from urllib.parse import urljoin

import django_rq
import redis
from cwe2.database import Database
from django.contrib.auth import get_user_model
from django.contrib.auth.models import UserManager
from django.core import exceptions
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.core.validators import MaxValueValidator
from django.core.validators import MinValueValidator
from django.db import models
from django.db.models import Count
from django.db.models import Exists
from django.db.models import OuterRef
from django.db.models import Q
from django.db.models import Subquery
from django.db.models.functions import Length
from django.db.models.functions import Trim
from django.urls import reverse
from django.utils import timezone
from packageurl import PackageURL
from packageurl.contrib.django.models import PackageURLMixin
from packageurl.contrib.django.models import PackageURLQuerySet
from rest_framework.authtoken.models import Token
from rq.command import send_stop_job_command
from rq.exceptions import NoSuchJobError
from rq.job import Job
from rq.job import JobStatus
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import AlpineLinuxVersionRange
from univers.versions import Version

import vulnerablecode
from vulnerabilities import utils
from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import compute_patch_checksum
from vulnerabilities.utils import normalize_list
from vulnerabilities.utils import normalize_purl
from vulnerabilities.utils import purl_to_dict
from vulnerablecode.settings import VULNERABLECODE_PIPELINE_TIMEOUT

logger = logging.getLogger(__name__)

models.CharField.register_lookup(Length)
models.CharField.register_lookup(Trim)

# patch univers for missing entry
RANGE_CLASS_BY_SCHEMES["apk"] = AlpineLinuxVersionRange


class BaseQuerySet(models.QuerySet):
    def get_or_none(self, *args, **kwargs):
        """
        Returns a single object matching the given keyword arguments, `None` otherwise.
        """
        with suppress(self.model.DoesNotExist, ValidationError):
            return self.get(*args, **kwargs)

    def paginated(self, per_page=5000):
        """
        Iterate over a (large) QuerySet by chunks of ``per_page`` items.
        This technique is essential for preventing memory issues when iterating
        See these links for inspiration:
        https://nextlinklabs.com/resources/insights/django-big-data-iteration
        https://stackoverflow.com/questions/4222176/why-is-iterating-through-a-large-django-queryset-consuming-massive-amounts-of-me/
        """
        paginator = Paginator(self, per_page=per_page)
        for page_number in paginator.page_range:
            page = paginator.page(page_number)
            for obj in page.object_list:
                yield obj


# FIXME: Remove when migration from Vulnerability to Advisory is completed
class VulnerabilityStatusType(models.IntegerChoices):
    """List of vulnerability statuses."""

    PUBLISHED = 1, "Published"
    DISPUTED = 2, "Disputed"
    INVALID = 3, "Invalid"


class AdvisoryStatusType(models.IntegerChoices):
    """List of vulnerability statuses."""

    PUBLISHED = 1, "Published"
    DISPUTED = 2, "Disputed"
    INVALID = 3, "Invalid"


# FIXME: Remove when migration from Vulnerability to Advisory is completed

UserModel = get_user_model()


class ApiUserManager(UserManager):
    def create_api_user(self, username, first_name="", last_name="", **extra_fields):
        """
        Create and return an API-only user. Raise ValidationError.
        """
        username = self.normalize_email(username)
        email = username
        self._validate_username(email)

        # note we use the email as username and we could instead override
        # django.contrib.auth.models.AbstractUser.USERNAME_FIELD

        user = self.create_user(
            username=email,
            email=email,
            password=None,
            first_name=first_name,
            last_name=last_name,
            **extra_fields,
        )

        # this ensure that this is not a valid password
        user.set_unusable_password()
        user.save()

        Token._default_manager.get_or_create(user=user)

        return user

    def _validate_username(self, email):
        """
        Validate username. If invalid, raise a ValidationError
        """
        try:
            self.get_by_natural_key(email)
        except models.ObjectDoesNotExist:
            pass
        else:
            raise exceptions.ValidationError(f"Error: This email already exists: {email}")


class ApiUser(UserModel):
    """A User proxy model to facilitate simplified admin API user creation."""

    objects = ApiUserManager()

    class Meta:
        proxy = True
        permissions = [
            (
                "throttle_3_unrestricted",
                "Can make unlimited API requests without any throttling limits",
            ),
            (
                "throttle_2_high",
                "Can make high number of API requests with minimal throttling",
            ),
            (
                "throttle_1_medium",
                "Can make medium number of API requests with standard throttling",
            ),
            (
                "throttle_0_low",
                "Can make low number of API requests with strict throttling",
            ),
        ]


class CodeChangeV2(models.Model):
    """
    Abstract base model representing a change in code, either introducing or fixing a vulnerability.
    This includes details about commits, patches, and related metadata.

    We are tracking commits, pulls and downloads as references to the code change. The goal is to
    keep track and store the actual code patch in the ``patch`` field. When not available the patch
    will be inferred from these references using improvers.
    """

    commits = models.JSONField(
        blank=True,
        default=list,
        help_text="List of commit identifiers using VCS URLs associated with the code change.",
    )
    pulls = models.JSONField(
        blank=True,
        default=list,
        help_text="List of pull request URLs associated with the code change.",
    )
    downloads = models.JSONField(
        blank=True, default=list, help_text="List of download URLs for the patched code."
    )
    patch = models.TextField(
        blank=True, null=True, help_text="The code change as a patch in unified diff format."
    )
    base_package_version = models.ForeignKey(
        "PackageV2",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="codechanges_v2",
        help_text="The base package version to which this code change applies.",
    )
    notes = models.TextField(
        blank=True, null=True, help_text="Notes or instructions about this code change."
    )
    references = models.JSONField(
        blank=True, default=list, help_text="URL references related to this code change."
    )
    is_reviewed = models.BooleanField(
        default=False, help_text="Indicates if this code change has been reviewed."
    )
    created_at = models.DateTimeField(
        auto_now_add=True, help_text="Timestamp indicating when this code change was created."
    )
    updated_at = models.DateTimeField(
        auto_now=True, help_text="Timestamp indicating when this code change was last updated."
    )

    class Meta:
        abstract = True


class CodeFixV2(CodeChangeV2):
    """
    A code fix is a code change that addresses a vulnerability and is associated:
    - with a specific advisory
    - package that has been affected
    - optionally with a specific fixing package version when it is known
    """

    advisory = models.ForeignKey(
        "AdvisoryV2",
        on_delete=models.CASCADE,
        related_name="code_fix_v2",
        help_text="The affected package version to which this code fix applies.",
    )

    affected_package = models.ForeignKey(
        "PackageV2", on_delete=models.CASCADE, related_name="code_fix_v2_affected"
    )

    fixed_package = models.ForeignKey(
        "PackageV2",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="code_fix_v2_fixed",
        help_text="The fixing package version with this code fix",
    )


class PipelineRun(models.Model):
    """The Database representation of a pipeline execution."""

    pipeline = models.ForeignKey(
        "PipelineSchedule",
        related_name="pipelineruns",
        on_delete=models.CASCADE,
    )

    run_id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        unique=True,
    )

    run_start_date = models.DateTimeField(
        blank=True,
        null=True,
        editable=False,
    )

    run_end_date = models.DateTimeField(
        blank=True,
        null=True,
        editable=False,
    )

    run_exitcode = models.IntegerField(
        null=True,
        blank=True,
        editable=False,
    )
    run_output = models.TextField(
        blank=True,
        editable=False,
    )

    created_date = models.DateTimeField(
        auto_now_add=True,
    )

    vulnerablecode_version = models.CharField(
        max_length=100,
        blank=True,
        null=True,
    )

    vulnerablecode_commit = models.CharField(
        max_length=300,
        blank=True,
        null=True,
    )

    log = models.TextField(
        blank=True,
        editable=False,
    )

    class Meta:
        ordering = ["-created_date"]

    class Status(models.TextChoices):
        UNKNOWN = "unknown"
        DISABLED = "disabled"
        RUNNING = "running"
        SUCCESS = "success"
        FAILURE = "failure"
        STOPPED = "stopped"
        QUEUED = "queued"
        STALE = "stale"

    @property
    def status(self):
        """Return current execution status."""
        status = self.Status

        if self.run_succeeded:
            return status.SUCCESS

        elif self.run_staled:
            return status.STALE

        elif self.run_stopped:
            return status.STOPPED

        elif self.run_failed:
            return status.FAILURE

        elif self.run_start_date:
            return status.RUNNING

        elif self.created_date:
            return status.QUEUED

        return status.UNKNOWN

    @property
    def pipeline_class(self):
        """Return the pipeline class."""
        return self.pipeline.pipeline_class

    @property
    def job(self):
        with suppress(redis.exceptions.ConnectionError, NoSuchJobError):
            return Job.fetch(
                str(self.run_id),
                connection=django_rq.get_connection(),
            )

    @property
    def job_status(self):
        job = self.job
        if job:
            return self.job.get_status()

    @property
    def run_succeeded(self):
        """Return True if the execution was successfully executed."""
        return self.run_exitcode == 0

    @property
    def run_failed(self):
        """Return True if the execution failed."""
        fail_exitcode = self.run_exitcode and self.run_exitcode > 0

        if not fail_exitcode:
            with suppress(redis.exceptions.ConnectionError, AttributeError):
                job = self.job
                if job.is_failed:
                    # Job was killed externally.
                    end_date = job.ended_at.replace(tzinfo=datetime.timezone.utc)
                    self.set_run_ended(
                        exitcode=1,
                        output=f"Killed from outside, exc_info={job.exc_info}",
                        end_date=end_date,
                    )
                    return True

        return fail_exitcode

    @property
    def run_stopped(self):
        """Return True if the execution was stopped."""
        return self.run_exitcode == 99

    @property
    def run_staled(self):
        """Return True if the execution staled."""
        return self.run_exitcode == 88

    @property
    def run_running(self):
        """Return True if the execution is running."""
        return self.status == self.Status.RUNNING

    @property
    def runtime(self):
        """Return the pipeline execution time."""
        if not self.run_start_date or (not self.run_end_date and not self.run_running):
            return

        end_time = self.run_end_date or timezone.now()
        time_delta = (end_time - self.run_start_date).total_seconds()
        return time_delta

    @property
    def pipeline_url(self):
        """Return pipeline URL based on commit and class module path."""
        if not self.vulnerablecode_commit:
            return None

        base_url = "https://github.com/aboutcode-org/vulnerablecode/blob/"
        module_path = self.pipeline_class.__module__.replace(".", "/") + ".py"
        relative_path = f"{self.vulnerablecode_commit}/{module_path}"

        return urljoin(base_url, relative_path)

    def set_vulnerablecode_version_and_commit(self):
        """Set the current VulnerableCode version and commit."""
        if self.vulnerablecode_version:
            msg = f"Field vulnerablecode_version already set to {self.vulnerablecode_version}"
            raise ValueError(msg)

        self.vulnerablecode_version = vulnerablecode.get_git_tag()
        self.vulnerablecode_commit = vulnerablecode.get_short_commit()
        self.save(update_fields=["vulnerablecode_version", "vulnerablecode_commit"])

    def set_run_started(self):
        """Reset the run and set `run_start_date` fields before starting run execution."""
        self.reset_run()
        self.run_start_date = timezone.now()
        self.save(update_fields=["run_start_date"])

    def set_run_ended(self, exitcode, output="", end_date=None):
        """Set the run-related fields after the run execution."""
        self.run_exitcode = exitcode
        self.run_output = output
        self.run_end_date = end_date or timezone.now()
        self.save(update_fields=["run_exitcode", "run_output", "run_end_date"])

    def set_run_staled(self):
        """Set the execution as `stale` using a special 88 exitcode value."""
        self.set_run_ended(exitcode=88)

    def set_run_stopped(self):
        """Set the execution as `stopped` using a special 99 exitcode value."""
        self.set_run_ended(exitcode=99)

    def reset_run(self):
        """Reset the run-related fields."""
        self.run_start_date = None
        self.run_end_date = None
        self.run_exitcode = None
        self.vulnerablecode_version = None
        self.vulnerablecode_commit = None
        self.run_output = ""
        self.log = ""
        self.save()

    def stop_run(self):
        if self.run_succeeded:
            return

        self.append_to_log("Stop run requested")
        if self.status == self.Status.QUEUED:
            self.dequeue()
            self.set_run_stopped()
            return

        if not self.job_status:
            self.set_run_staled()
            return

        if self.job_status == JobStatus.FAILED:
            job = self.job
            end_date = job.ended_at.replace(tzinfo=datetime.timezone.utc)
            self.set_run_ended(
                exitcode=1,
                output=f"Killed from outside, exc_info={job.exc_info}",
                end_date=end_date,
            )
            return

        send_stop_job_command(
            connection=django_rq.get_connection(),
            job_id=str(self.run_id),
        )
        self.set_run_stopped()
        self.delete_run_job()

    def delete_run_job(self):
        if job := self.job:
            job.delete()

    def delete(self, *args, **kwargs):
        """
        Before deletion of the run instance, try to stop the run execution.
        """
        with suppress(redis.exceptions.ConnectionError, AttributeError):
            self.stop_run()

        self.delete_run_job()

        return super().delete(*args, **kwargs)

    def append_to_log(self, message, is_multiline=False):
        """Append ``message`` to log field of run instance."""
        message = message.strip()
        if not is_multiline:
            message = message.replace("\n", "").replace("\r", "")

        self.log = self.log + message + "\n"
        self.save(update_fields=["log"])

    def dequeue(self):
        from vulnerabilities.tasks import dequeue_job

        dequeue_job(self.run_id)

    def requeue(self):
        """Reset run and requeue pipeline for execution."""
        if job := self.job:
            self.reset_run()
            return job.requeue()


class PipelineSchedule(models.Model):
    """The Database representation of a pipeline schedule."""

    class ExecutionPriority(models.IntegerChoices):
        HIGH = 1, "high"
        DEFAULT = 2, "default"

    pipeline_id = models.CharField(
        max_length=600,
        help_text=("Identify a registered Pipeline class."),
        unique=True,
        blank=False,
        null=False,
    )

    is_active = models.BooleanField(
        null=True,
        db_index=True,
        default=True,
        help_text=(
            "When set to True, this Pipeline is active. "
            "When set to False, this Pipeline is inactive and not run."
        ),
    )

    is_run_once = models.BooleanField(
        null=False,
        db_index=True,
        default=False,
        help_text=("When set to True, this Pipeline will run only once."),
    )

    live_logging = models.BooleanField(
        null=False,
        db_index=True,
        default=False,
        help_text=(
            "When enabled logs will be streamed live during pipeline execution. "
            "For legacy importers and improvers, logs are always made available only after execution completes."
        ),
    )

    run_interval = models.IntegerField(
        validators=[
            MinValueValidator(5, message="Interval must be at least 5 minutes."),
            MaxValueValidator(
                43200, message="Interval must be at most 43200 minutes (i.e 30 days)."
            ),
        ],
        default=1440,
        help_text=("Number of minutes to wait between run of this pipeline."),
    )

    run_priority = models.IntegerField(
        null=False,
        blank=False,
        choices=ExecutionPriority.choices,
        default=ExecutionPriority.DEFAULT,
        help_text=("Select the pipeline execution priority"),
    )

    schedule_work_id = models.CharField(
        max_length=255,
        unique=True,
        null=True,
        blank=True,
        db_index=True,
        help_text=("Identifier used to manage the periodic run job."),
    )

    execution_timeout = models.PositiveSmallIntegerField(
        validators=[
            MinValueValidator(1, message="Pipeline timeout must be at least 1 hour."),
            MaxValueValidator(72, message="Pipeline timeout must be at most 72 hours."),
        ],
        default=VULNERABLECODE_PIPELINE_TIMEOUT,
        help_text=("Number hours before pipeline execution is forcefully terminated."),
    )

    created_date = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
    )

    class Meta:
        ordering = ["-created_date"]

    def __str__(self):
        return f"{self.pipeline_id}"

    def save(self, *args, **kwargs):
        if not self.pk:
            self.schedule_work_id = self.create_new_job(execute_now=True)
        elif self.pk and (existing := PipelineSchedule.objects.get(pk=self.pk)):
            if (
                existing.is_active != self.is_active
                or existing.run_interval != self.run_interval
                or existing.run_priority != self.run_priority
            ):
                self.schedule_work_id = self.create_new_job()
        self.full_clean()
        return super().save(*args, **kwargs)

    @property
    def pipeline_class(self):
        """Return the pipeline class."""

        from vulnerabilities.importers import IMPORTERS_REGISTRY
        from vulnerabilities.improvers import IMPROVERS_REGISTRY
        from vulnerabilities.pipelines.exporters import EXPORTERS_REGISTRY
        from vulnerabilities.pipelines.management import MANAGEMENT_REGISTRY

        pipeline_registry = (
            IMPORTERS_REGISTRY | IMPROVERS_REGISTRY | EXPORTERS_REGISTRY | MANAGEMENT_REGISTRY
        )

        return pipeline_registry[self.pipeline_id]

    @property
    def description(self):
        """Return the pipeline class."""

        if self.pipeline_class:
            return cleandoc(self.pipeline_class.__doc__ or "")

    @property
    def all_runs(self):
        """Return all the previous run instances for this pipeline."""
        return self.pipelineruns.all()

    @property
    def latest_run(self):
        return self.pipelineruns.first() if self.pipelineruns.exists() else None

    @property
    def latest_successful_run(self):
        successful_runs = self.pipelineruns.filter(run_end_date__isnull=False, run_exitcode=0)
        return successful_runs.first() if successful_runs.exists() else None

    @property
    def earliest_run(self):
        return self.pipelineruns.earliest("run_start_date") if self.pipelineruns.exists() else None

    @property
    def latest_run_date(self):
        if not self.pipelineruns.exists():
            return
        latest_run = self.pipelineruns.values("run_start_date").first()
        return latest_run["run_start_date"]

    @property
    def latest_run_end_date(self):
        if not self.pipelineruns.exists():
            return
        latest_run = self.pipelineruns.values("run_end_date").first()
        return latest_run["run_end_date"]

    @property
    def next_run_date(self):
        if not self.is_active:
            return

        current_date_time = datetime.datetime.now(tz=datetime.timezone.utc)
        if self.latest_run_date:
            next_execution = self.latest_run_date + datetime.timedelta(minutes=self.run_interval)
            if next_execution > current_date_time:
                return next_execution

        return current_date_time

    @property
    def status(self):
        if not self.is_active:
            return PipelineRun.Status.DISABLED

        if self.pipelineruns.exists():
            latest = self.pipelineruns.only("pk").first()
            return latest.status

    def create_new_job(self, execute_now=False):
        """
        Create a new scheduled job. If a previous scheduled job
        exists remove the existing job from the scheduler.
        """
        from vulnerabilities import schedules

        if not schedules.is_redis_running():
            return
        if self.schedule_work_id:
            schedules.clear_job(self.schedule_work_id)

        return schedules.schedule_execution(self, execute_now) if self.is_active else None


ISSUE_TYPE_CHOICES = [
    ("MISSING_AFFECTED_PACKAGE", "Advisory is missing affected package"),
    ("MISSING_FIXED_BY_PACKAGE", "Advisory is missing fixed-by package"),
    (
        "MISSING_AFFECTED_AND_FIXED_BY_PACKAGES",
        "Advisory is missing both affected and fixed-by packages",
    ),
    ("MISSING_SUMMARY", "Advisory is missing summary"),
    ("CONFLICTING_FIXED_BY_PACKAGES", "Advisories have conflicting fixed-by packages"),
    ("CONFLICTING_AFFECTED_PACKAGES", "Advisories have conflicting affected packages"),
    (
        "CONFLICTING_AFFECTED_AND_FIXED_BY_PACKAGES",
        "Advisories have conflicting affected and fixed-by packages",
    ),
    ("CONFLICTING_SEVERITY_SCORES", "Advisories have conflicting severity scores"),
    ("CONFLICTING_WEAKNESSES", "Advisories have conflicting weaknesses"),
]


class AdvisoryToDoV2QuerySet(models.QuerySet):

    def exclude_stale(self):
        return self.exclude(is_todo_stale=True)


class AdvisoryToDoV2(models.Model):
    """Track the TODOs for advisory/ies that need to be addressed."""

    todo_id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    # Since we can not make advisories field (M2M field) unique
    # (see https://code.djangoproject.com/ticket/702), we use related_advisories_id
    # to avoid creating duplicate issue for same set of advisories,
    related_advisories_id = models.CharField(
        max_length=40,
        help_text="SHA1 digest of the unique_content_id field of the applicable advisories.",
    )

    advisories = models.ManyToManyField(
        "AdvisoryV2",
        through="ToDoRelatedAdvisoryV2",
        related_name="advisory_todos",
        help_text="Advisory/ies where this TODO is applicable.",
    )

    alias = models.CharField(
        max_length=50,
        db_index=True,
        blank=False,
        null=False,
        help_text="Alias associated with TODO advisories",
    )

    advisories_count = models.IntegerField(
        help_text="Number of advisory associated with this TODO.",
        default=1,
        db_index=True,
    )

    issue_type = models.CharField(
        max_length=50,
        choices=ISSUE_TYPE_CHOICES,
        db_index=True,
        help_text="Select the issue that needs to be addressed from the available options.",
    )

    issue_detail = models.JSONField(
        blank=True,
        default=dict,
        help_text="Additional details about the issue.",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="Timestamp indicating when this TODO was created.",
    )

    is_resolved = models.BooleanField(
        default=False,
        db_index=True,
        help_text="This TODO is resolved or not.",
    )

    resolved_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp indicating when this TODO was resolved.",
    )

    resolution_detail = models.TextField(
        blank=True,
        help_text="Additional detail on how this TODO was resolved.",
    )

    oldest_advisory_date = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        help_text="Timestamp indicating when the oldest advisory was published, used for triaging TODOs.",
    )

    is_todo_stale = models.BooleanField(
        null=False,
        db_index=True,
        default=False,
        help_text="TODOs are marked stale if associate advisory is no longer the latest version of the advisory.",
    )

    objects = AdvisoryToDoV2QuerySet.as_manager()

    class Meta:
        unique_together = ("related_advisories_id", "issue_type")


class AdvisorySeverity(models.Model):
    url = models.URLField(
        max_length=1024,
        null=True,
        help_text="URL to the vulnerability severity",
        db_index=True,
    )

    scoring_system_choices = tuple(
        (system.identifier, system.name) for system in SCORING_SYSTEMS.values()
    )

    scoring_system = models.CharField(
        max_length=50,
        choices=scoring_system_choices,
        help_text="Identifier for the scoring system used. Available choices are: {} ".format(
            ",\n".join(f"{sid}: {sname}" for sid, sname in scoring_system_choices)
        ),
    )

    # A severity value might be missing and it may just contain scoring_elements only
    value = models.CharField(max_length=50, help_text="Example: 9.0, Important, High", null=True)

    scoring_elements = models.CharField(
        max_length=250,
        null=True,
        help_text="Supporting scoring elements used to compute the score values. "
        "For example a CVSS vector string as used to compute a CVSS score.",
    )

    published_at = models.DateTimeField(
        blank=True, null=True, help_text="UTC Date of publication of the vulnerability severity"
    )

    objects = BaseQuerySet.as_manager()

    class Meta:
        verbose_name_plural = "Advisory severities"
        ordering = ["url", "scoring_system", "value"]
        unique_together = ("url", "scoring_system", "value", "scoring_elements", "published_at")
        constraints = [
            models.CheckConstraint(
                check=(
                    Q(value__isnull=False) & ~Q(value="")
                    | Q(scoring_elements__isnull=False) & ~Q(scoring_elements="")
                ),
                name="scoring_elements_or_value_must_be_set",
            )
        ]

    def to_dict(self):
        return {
            "system": self.scoring_system,
            "value": self.value,
            "scoring_elements": self.scoring_elements,
            "published_at": self.published_at,
            "url": self.url,
        }

    def to_vulnerability_severity_data(self):
        from vulnerabilities.importer import VulnerabilitySeverity

        return VulnerabilitySeverity.from_dict(self.to_dict())


class AdvisoryWeakness(models.Model):
    """
    A weakness is a software weakness that is associated with a vulnerability.
    """

    cwe_id = models.IntegerField(help_text="CWE id", unique=True)

    cwe_by_id = {}

    class Meta:
        verbose_name_plural = "Advisory weaknesses"

    def get_cwe(self, cwe_id):
        if not self.cwe_by_id:
            db = Database()
            for weakness in db.get_cwes():
                self.cwe_by_id[str(weakness.cwe_id)] = weakness
        return self.cwe_by_id[cwe_id]

    @property
    def cwe(self):
        return f"CWE-{self.cwe_id}"

    @property
    def weakness(self):
        """
        Return a queryset of Weakness for this vulnerability.
        """
        try:
            weakness = self.get_cwe(str(self.cwe_id))
            return weakness
        except Exception as e:
            logger.warning(f"Could not find CWE {self.cwe_id}: {e}")

    @property
    def name(self):
        """Return the weakness's name."""
        return self.weakness.name if self.weakness else ""

    @property
    def description(self):
        """Return the weakness's description."""
        return self.weakness.description if self.weakness else ""

    def to_dict(self):
        return {"cwe_id": self.cwe_id, "name": self.name, "description": self.description}


class AdvisoryReference(models.Model):
    url = models.URLField(
        max_length=1024,
        help_text="URL to the vulnerability reference",
    )

    archive_url = models.URLField(
        max_length=1024,
        null=True,
        help_text="URL to the backup vulnerability reference",
    )

    ADVISORY = "advisory"
    EXPLOIT = "exploit"
    COMMIT = "commit"
    MAILING_LIST = "mailing_list"
    BUG = "bug"
    OTHER = "other"

    REFERENCE_TYPES = [
        (ADVISORY, "Advisory"),
        (EXPLOIT, "Exploit"),
        (COMMIT, "Commit"),
        (MAILING_LIST, "Mailing List"),
        (BUG, "Bug"),
        (OTHER, "Other"),
    ]

    reference_type = models.CharField(max_length=20, choices=REFERENCE_TYPES, blank=True)

    reference_id = models.CharField(
        max_length=500,
        help_text="An optional reference ID, such as DSA-4465-1 when available",
        blank=True,
        db_index=True,
    )

    class Meta:
        ordering = ["reference_id", "url", "reference_type"]
        unique_together = ("url", "reference_type")

    def __str__(self):
        reference_id = f" {self.reference_id}" if self.reference_id else ""
        return f"{self.url}{reference_id}"

    @property
    def is_cpe(self):
        """
        Return True if this is a CPE reference.
        """
        return self.reference_id.startswith("cpe")

    def to_dict(self):
        return {
            "reference_id": self.reference_id,
            "reference_type": self.reference_type,
            "url": self.url,
        }

    def to_reference_v2_data(self):
        from vulnerabilities.importer import ReferenceV2

        return ReferenceV2.from_dict(self.to_dict())


class AdvisoryAlias(models.Model):
    alias = models.CharField(
        max_length=50,
        unique=True,
        blank=False,
        null=False,
        help_text="An alias is a unique vulnerability identifier in some database, "
        "such as CVE-2020-2233",
    )

    class Meta:
        verbose_name_plural = "Advisory aliases"
        ordering = ["alias"]

    def __str__(self):
        return self.alias

    @cached_property
    def url(self):
        """
        Create a URL for the alias.
        """
        alias: str = self.alias
        if alias.startswith("CVE"):
            return f"https://nvd.nist.gov/vuln/detail/{alias}"

        if alias.startswith("GHSA"):
            return f"https://github.com/advisories/{alias}"

        if alias.startswith("NPM-"):
            id = alias.lstrip("NPM-")
            return f"https://github.com/nodejs/security-wg/blob/main/vuln/npm/{id}.json"


class Patch(models.Model):
    """
    A generic patch linked to an advisory.
    Used for raw text patches, fallback scenarios, or unsupported VCS types.
    """

    patch_url = models.URLField(
        null=True,
        blank=True,
        help_text="URL to the patch file or diff.",
    )

    patch_text = models.TextField(
        null=True,
        blank=True,
        help_text="The actual text content of the code patch/diff.",
    )

    patch_checksum = models.CharField(
        max_length=128,
        blank=True,
        null=True,
        help_text="SHA512 checksum of the patch content.",
    )

    def save(self, *args, **kwargs):
        if self.patch_text:
            self.patch_checksum = compute_patch_checksum(self.patch_text)
        super().save(*args, **kwargs)

    class Meta:
        unique_together = ["patch_checksum", "patch_url"]
        constraints = [
            models.CheckConstraint(
                check=(
                    Q(patch_url__isnull=False) & ~Q(patch_url="")
                    | Q(patch_text__isnull=False) & ~Q(patch_text="")
                ),
                name="patch_url_or_patch_text",
            )
        ]

    def to_dict(self):
        return {
            "patch_url": self.patch_url,
            "patch_text": self.patch_text,
            "patch_checksum": self.patch_checksum,
        }

    def to_patch_data(self):
        """Return `PatchData` from the Patch."""
        from vulnerabilities.importer import PatchData

        return PatchData.from_dict(self.to_dict())


class PackageCommitPatch(models.Model):
    """
    A specific patch implementation for structured Package/VCS data
    """

    commit_hash = models.CharField(
        max_length=128,
        help_text="The commit hash of the patch in the VCS.",
    )

    vcs_url = models.URLField(
        max_length=1024,
        help_text="The Version Control System URL (e.g., git repo URL).",
    )

    patch_text = models.TextField(blank=True, null=True)
    patch_checksum = models.CharField(max_length=128, blank=True, null=True)

    def save(self, *args, **kwargs):
        if self.patch_text:
            self.patch_checksum = compute_patch_checksum(self.patch_text)
        super().save(*args, **kwargs)

    class Meta:
        unique_together = ["commit_hash", "vcs_url"]

    def to_dict(self):
        return {
            "vcs_url": self.vcs_url,
            "commit_hash": self.commit_hash,
            "patch_text": self.patch_text,
            "patch_checksum": self.patch_checksum,
        }


class AdvisoryV2QuerySet(BaseQuerySet):
    def latest_for_avid(self, avid: str):
        try:
            return self.get(avid=avid, is_latest=True)
        except self.model.DoesNotExist:
            return None

    def latest_per_avid(self):
        return self.filter(is_latest=True)

    def latest_for_avids(self, avids):
        return self.filter(avid__in=avids).latest_per_avid()

    def latest_for_avid_completely_imported_advisories(self, avid):
        return self.get(avid=avid, is_latest=True, _all_impacts_unfurled_at__isnull=False)

    def latest_completely_imported_advisories_per_avid(self):
        return self.filter(is_latest=True, _all_impacts_unfurled_at__isnull=False)

    def latest_for_avids_completely_imported_advisories(self, avids):
        return self.get(avid__in=avids, is_latest=True, _all_impacts_unfurled_at__isnull=False)

    def latest_affecting_advisories_for_purl(self, purl):
        adv_ids = ImpactedPackageAffecting.objects.filter(
            package__package_url=purl,
            impacted_package__advisory__is_latest=True,
            impacted_package__advisory___all_impacts_unfurled_at__isnull=False,
        ).values_list("impacted_package__advisory_id", flat=True)

        return self.filter(id__in=Subquery(adv_ids))

    def latest_affecting_advisories_for_purls(self, purls):
        adv_ids = ImpactedPackageAffecting.objects.filter(
            package__package_url__in=purls,
            impacted_package__advisory__is_latest=True,
            impacted_package__advisory___all_impacts_unfurled_at__isnull=False,
        ).values_list(
            "impacted_package__advisory_id",
            flat=True,
        )
        return self.filter(id__in=Subquery(adv_ids))

    def latest_affecting_advisory_purls_pairs(self, purls):
        return (
            ImpactedPackageAffecting.objects.filter(
                package__package_url__in=purls,
                impacted_package__advisory__is_latest=True,
                impacted_package__advisory___all_impacts_unfurled_at__isnull=False,
            )
            .values_list(
                "package__package_url",
                "impacted_package__advisory_id",
            )
            .distinct()
        )

    def latest_fixed_by_advisories_for_purl(self, purl):
        adv_ids = ImpactedPackageFixedBy.objects.filter(
            package__package_url=purl,
            impacted_package__advisory__is_latest=True,
            impacted_package__advisory___all_impacts_unfurled_at__isnull=False,
        ).values_list(
            "impacted_package__advisory_id",
            flat=True,
        )
        return self.filter(id__in=Subquery(adv_ids))

    def latest_fixed_by_advisories_for_purls(self, purls):
        adv_ids = ImpactedPackageFixedBy.objects.filter(
            package_url__in=purls,
            impacted_package__advisory__is_latest=True,
            impacted_package__advisory___all_impacts_unfurled_at__isnull=False,
        ).values_list(
            "impacted_package__advisory_id",
            flat=True,
        )

        return self.filter(id__in=Subquery(adv_ids))

    def latest_fixed_by_advisory_purls_pairs(self, purls):
        return (
            ImpactedPackageFixedBy.objects.filter(
                package__package_url__in=purls,
                impacted_package__advisory__is_latest=True,
                impacted_package__advisory___all_impacts_unfurled_at__isnull=False,
            )
            .values_list(
                "package__package_url",
                "impacted_package__advisory_id",
            )
            .distinct()
        )

    def latest_advisories_for_purls(self, purls):
        adv_ids = (
            ImpactedPackage.objects.filter(
                affecting_packages__package_url__in=purls,
                advisory__is_latest=True,
                advisory___all_impacts_unfurled_at__isnull=False,
            )
            .values_list(
                "advisory_id",
                flat=True,
            )
            .union(
                ImpactedPackage.objects.filter(
                    fixed_by_packages__package_url__in=purls,
                    advisory__is_latest=True,
                    advisory___all_impacts_unfurled_at__isnull=False,
                ).values_list(
                    "advisory_id",
                    flat=True,
                )
            )
        )

        qs = self.filter(id__in=Subquery(adv_ids))
        return qs

    def latest_advisories_for_purl(self, purl):
        adv_ids = (
            ImpactedPackage.objects.filter(
                affecting_packages__package_url=purl,
                advisory__is_latest=True,
                advisory___all_impacts_unfurled_at__isnull=False,
            )
            .values_list(
                "advisory_id",
                flat=True,
            )
            .union(
                ImpactedPackage.objects.filter(
                    fixed_by_packages__package_url=purl,
                    advisory__is_latest=True,
                    advisory___all_impacts_unfurled_at__isnull=False,
                ).values_list(
                    "advisory_id",
                    flat=True,
                )
            )
        )

        qs = self.filter(id__in=Subquery(adv_ids))
        return qs

    def todo_excluded(self):
        """Exclude advisory ineligible for ToDo computation."""
        from vulnerabilities.importers import TODO_EXCLUDED_PIPELINES

        return self.exclude(pipeline_id__in=TODO_EXCLUDED_PIPELINES)


class AdvisorySet(models.Model):

    RELATION_TYPE_CHOICES = [
        ("affecting", "Affecting"),
        ("fixing", "Fixing"),
    ]

    package = models.ForeignKey("PackageV2", on_delete=models.CASCADE)
    relation_type = models.CharField(max_length=20, choices=RELATION_TYPE_CHOICES, db_index=True)

    aliases = models.ManyToManyField(
        AdvisoryAlias,
        related_name="advisory_sets",
        help_text="A list of serializable Alias objects",
    )

    primary_advisory = models.ForeignKey("AdvisoryV2", on_delete=models.PROTECT)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("package", "relation_type", "primary_advisory")
        indexes = [
            models.Index(fields=["package", "relation_type"]),
        ]


class AdvisorySetMember(models.Model):

    advisory_set = models.ForeignKey(
        AdvisorySet,
        on_delete=models.CASCADE,
        related_name="members",
    )

    advisory = models.ForeignKey("AdvisoryV2", on_delete=models.CASCADE)
    is_primary = models.BooleanField(default=False)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["advisory_set", "advisory"],
                name="unique_advisory_per_set",
            ),
        ]


class AdvisoryV2(models.Model):
    """
    An advisory represents data directly obtained from upstream transformed
    into structured data
    """

    # This is similar to a type or a namespace
    datasource_id = models.CharField(
        max_length=50,
        blank=False,
        null=False,
        db_index=True,
        help_text="Unique ID for the datasource used for this advisory ." "e.g.: nginx",
    )

    pipeline_id = models.CharField(
        max_length=50,
        blank=False,
        null=False,
        db_index=True,
        help_text="Unique ID for the pipeline used for this advisory ." "e.g.: nginx_importer_v2",
    )

    # This is similar to a name
    advisory_id = models.CharField(
        max_length=200,
        blank=False,
        null=False,
        unique=False,
        db_index=True,
        help_text="An advisory is a unique vulnerability identifier in some database, "
        "such as PYSEC-2020-2233",
    )

    avid = models.CharField(
        max_length=250,
        blank=False,
        null=False,
        help_text="Unique ID for the datasource used for this advisory ."
        "e.g.: pysec_importer_v2/PYSEC-2020-2233",
    )

    # This is similar to a version
    unique_content_id = models.CharField(
        max_length=64,
        blank=False,
        null=False,
        unique=True,
        help_text="A 64 character unique identifier for the content of the advisory since we use sha256 as hex",
    )
    url = models.URLField(
        blank=False,
        null=False,
        help_text="Link to the advisory on the upstream website",
    )

    # TODO: Have a mapping that gives datasource class by datasource ID
    # Get label from datasource class
    # Remove this from model
    # In the UI - Use label
    # In the API - Use datasource_id
    # Have an API endpoint for all info for datasources - show license, label

    summary = models.TextField(
        blank=True,
    )
    aliases = models.ManyToManyField(
        AdvisoryAlias,
        related_name="advisories",
        help_text="A list of serializable Alias objects",
    )
    references = models.ManyToManyField(
        AdvisoryReference,
        related_name="advisories",
        help_text="A list of serializable Reference objects",
    )
    severities = models.ManyToManyField(
        AdvisorySeverity,
        related_name="advisories",
        help_text="A list of vulnerability severities associated with this advisory.",
    )
    weaknesses = models.ManyToManyField(
        AdvisoryWeakness,
        related_name="advisories",
        help_text="A list of software weaknesses associated with this advisory.",
    )

    patches = models.ManyToManyField(
        Patch,
        related_name="advisories",
        help_text="A list of patches associated with this advisory.",
    )

    resolves_todos = models.ManyToManyField(
        AdvisoryToDoV2,
        related_name="resolved_in_advisories",
        help_text="A list of Advisory ToDos resolved by this advisory.",
    )

    is_curation = models.BooleanField(
        default=False,
        blank=False,
        null=False,
        db_index=True,
        help_text="Indicates whether this is a curation advisory.",
    )

    date_published = models.DateTimeField(
        blank=True,
        null=True,
        help_text="UTC Date of publication of the advisory",
    )
    date_collected = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="UTC Date on which the advisory was collected",
    )

    is_latest = models.BooleanField(
        default=False,
        blank=False,
        null=False,
        db_index=True,
        help_text="Indicates whether this is the latest version of the advisory identified by its AVID.",
    )

    original_advisory_text = models.TextField(
        blank=True,
        null=True,
        help_text="Raw advisory data as collected from the upstream datasource.",
    )

    status = models.IntegerField(
        choices=AdvisoryStatusType.choices, default=AdvisoryStatusType.PUBLISHED
    )

    # Note: Fields and relations below are not part of original upstream advisory.

    exploitability = models.DecimalField(
        null=True,
        blank=True,
        max_digits=2,
        decimal_places=1,
        help_text="Exploitability indicates the likelihood that a vulnerability in a software package could be used by malicious actors to compromise systems, "
        "applications, or networks. This metric is determined automatically based on the discovery of known exploits.",
    )

    weighted_severity = models.DecimalField(
        null=True,
        blank=True,
        max_digits=3,
        decimal_places=1,
        help_text="Weighted severity is the highest value calculated by multiplying each severity by its corresponding weight, divided by 10.",
    )

    precedence = models.IntegerField(
        null=True,
        blank=True,
        help_text="Precedence indicates the priority of advisory from different datasources. It is determined based on the reliability of the datasource and how close it is to the source.",
    )

    related_advisory_severities = models.ManyToManyField(
        "AdvisoryV2",
        related_name="related_to_advisory_severities",
        help_text="Related advisories that are used to calculate the severity of this advisory.",
    )

    risk_score = models.DecimalField(
        null=True,
        blank=True,
        max_digits=3,
        decimal_places=1,
        help_text="Risk expressed as a number ranging from 0 to 10. Risk is calculated from weighted severity and exploitability values. It is the maximum value of (the weighted severity multiplied by its exploitability) or 10. Risk = min(weighted severity * exploitability, 10)",
    )

    _all_impacts_unfurled_at = models.DateTimeField(
        help_text="Indicates whether all impacts for this advisory have been unfurled.",
        db_index=True,
        blank=True,
        null=True,
    )

    _all_impacts_unfurled_successfully_at = models.DateTimeField(
        help_text="Indicates whether all impacts for this advisory have been unfurled successfully.",
        db_index=True,
        blank=True,
        null=True,
    )

    objects = AdvisoryV2QuerySet.as_manager()

    class Meta:
        unique_together = ["datasource_id", "advisory_id", "unique_content_id"]
        ordering = ["datasource_id", "advisory_id", "date_published", "unique_content_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["avid"], condition=Q(is_latest=True), name="unique_latest_per_avid"
            )
        ]
        indexes = [
            models.Index(fields=["is_latest", "_all_impacts_unfurled_at"]),
        ]

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)

    def __str__(self):
        return self.avid

    @property
    def get_status_label(self):
        label_by_status = {choice[0]: choice[1] for choice in VulnerabilityStatusType.choices}
        return label_by_status.get(self.status) or VulnerabilityStatusType.PUBLISHED.label

    def get_absolute_url(self):
        """
        Return this Vulnerability details absolute URL.
        """
        return reverse("advisory_details", args=[self.avid])

    def to_advisory_data(self) -> "AdvisoryDataV2":
        from vulnerabilities.importer import AdvisoryDataV2

        return AdvisoryDataV2(
            advisory_id=self.advisory_id,
            aliases=normalize_list([item.alias for item in self.aliases.all()]),
            summary=self.summary,
            affected_packages=normalize_list(
                [impacted.to_affected_package_data() for impacted in self.impacted_packages.all()]
            ),
            references=normalize_list(
                [ref.to_reference_v2_data() for ref in self.references.all()]
            ),
            patches=normalize_list([patch.to_patch_data() for patch in self.patches.all()]),
            date_published=self.date_published,
            weaknesses=normalize_list([weak.cwe_id for weak in self.weaknesses.all()]),
            severities=normalize_list(
                [sev.to_vulnerability_severity_data() for sev in self.severities.all()]
            ),
            url=self.url,
        )

    @property
    def get_aliases(self):
        """
        Return a queryset of all Aliases for this vulnerability.
        """
        return self.aliases.all()

    alias = get_aliases


class ImpactedPackage(models.Model):
    """
    Represents a single impact for an advisory, including affected range and fixed version and
    associated package relations.
    """

    advisory = models.ForeignKey(
        AdvisoryV2,
        related_name="impacted_packages",
        on_delete=models.CASCADE,
    )

    base_purl = models.CharField(
        max_length=500,
        blank=False,
        help_text="Version less PURL related to impacted range.",
    )

    affecting_vers = models.TextField(
        blank=True,
        null=True,
        help_text="VersionRange expression for package vulnerable to this impact.",
    )

    fixed_vers = models.TextField(
        blank=True,
        null=True,
        help_text="VersionRange expression for packages fixing the vulnerable package in this impact.",
    )

    affecting_packages = models.ManyToManyField(
        "PackageV2",
        related_name="affected_in_impacts",
        through="ImpactedPackageAffecting",
        help_text="Packages vulnerable to this impact.",
    )

    fixed_by_packages = models.ManyToManyField(
        "PackageV2",
        related_name="fixed_in_impacts",
        through="ImpactedPackageFixedBy",
        help_text="Packages fixing the vulnerable packages in this impact.",
    )

    introduced_by_package_commit_patches = models.ManyToManyField(
        "PackageCommitPatch",
        related_name="introduced_in_impacts",
        help_text="PackageCommitPatches that introduce this impact.",
    )

    fixed_by_package_commit_patches = models.ManyToManyField(
        "PackageCommitPatch",
        related_name="fixed_in_impacts",
        help_text="PackageCommitPatches that fix this impact.",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text="Timestamp indicating when this impact was added.",
    )

    last_range_unfurl_at = models.DateTimeField(
        blank=True,
        null=True,
        db_index=True,
        help_text="Timestamp of the last vers range unfurl.",
    )

    last_successful_range_unfurl_at = models.DateTimeField(
        blank=True,
        null=True,
        db_index=True,
        help_text="Timestamp of the last successful vers range unfurl.",
    )

    def to_dict(self):
        from vulnerabilities.utils import purl_to_dict

        return {
            "package": purl_to_dict(self.base_purl),
            "affected_version_range": self.affecting_vers,
            "fixed_version_range": self.fixed_vers,
            "introduced_by_commit_patches": [
                commit.to_dict() for commit in self.introduced_by_package_commit_patches.all()
            ],
            "fixed_by_commit_patches": [
                commit.to_dict() for commit in self.fixed_by_package_commit_patches.all()
            ],
        }

    def to_affected_package_data(self):
        """Return `AffectedPackageV2` data from the impact."""
        from vulnerabilities.importer import AffectedPackageV2

        return AffectedPackageV2.from_dict(self.to_dict())

    class Meta:
        indexes = [
            models.Index(fields=["advisory", "last_range_unfurl_at"]),
        ]


class AdvisoryMitigations(models.Model):

    advisory = models.ForeignKey(
        AdvisoryV2,
        related_name="mitigations",
        on_delete=models.CASCADE,
    )

    base_purl = models.CharField(
        max_length=500,
        blank=False,
        help_text="Version less PURL related to mitigation.",
    )

    upgrade_to_versions = models.ManyToManyField(
        "PackageV2",
        blank=True,
        related_name="upgrade_mitigations",
        help_text="Packages that mitigates the advisory by upgrading.",
    )
    upgrade_to_versions_note = models.TextField(blank=True)

    downgrade_to_versions = models.ManyToManyField(
        "PackageV2",
        blank=True,
        related_name="downgrade_mitigations",
        help_text="Packages that mitigates the advisory by downgrading.",
    )
    downgrade_to_versions_note = models.TextField(blank=True)

    patches = models.ManyToManyField(
        "PackageCommitPatch",
        related_name="patch_mitigations",
        help_text="Patches to mitigate the advisory.",
    )
    patches_note = models.TextField(blank=True)

    config_change = models.TextField(
        blank=True,
        help_text="Configuration change to mitigate the advisory.",
    )
    config_change_note = models.TextField(blank=True)

    filter_ports_ips = models.TextField(
        blank=True,
        help_text="Filter Ports and IPs to mitigate the advisory.",
    )
    filter_ports_ips_note = models.TextField(blank=True)

    replace_with_packages = models.ManyToManyField(
        "PackageV2",
        blank=True,
        related_name="replacement_mitigations",
        help_text="Packages that can replace the vulnerable package.",
    )
    replace_package_note = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class ToDoRelatedAdvisoryV2(models.Model):
    todo = models.ForeignKey(
        AdvisoryToDoV2,
        on_delete=models.CASCADE,
    )

    advisory = models.ForeignKey(
        AdvisoryV2,
        on_delete=models.CASCADE,
    )

    class Meta:
        unique_together = ("todo", "advisory")


class PackageQuerySetV2(BaseQuerySet, PackageURLQuerySet):
    def search(self, query: str = None):
        """
        Return a Package queryset searching for the ``query``.
        Make a best effort approach to find matching packages either based
        on exact purl, partial purl or just name and namespace.
        """
        query = query and query.strip()
        if not query:
            return self.none()
        qs = self

        try:
            # if it's a valid purl, try to parse it and use it as is
            purl = str(utils.plain_purl(query))
            qs = qs.filter(package_url__istartswith=purl)
        except ValueError:
            # otherwise use query as a plain string
            qs = qs.filter(package_url__icontains=query)
        return qs.order_by("type", "namespace", "name", "-version_rank")

    def with_vulnerability_counts(self):
        return self.annotate(
            vulnerability_count=Count(
                "affected_in_impacts__advisory",
                distinct=True,
            ),
            patched_vulnerability_count=Count(
                "fixed_in_impacts__advisory",
                distinct=True,
            ),
        )

    def get_fixed_by_package_versions(self, purl: PackageURL, fix=True):
        """
        Return a queryset of all the package versions of this `package` that fix any vulnerability.
        If `fix` is False, return all package versions whether or not they fix a vulnerability.
        """
        filter_dict = {
            "name": purl.name,
            "namespace": purl.namespace,
            "type": purl.type,
            "qualifiers": purl.qualifiers,
            "subpath": purl.subpath,
        }

        if fix:
            filter_dict["fixed_in_impacts__isnull"] = False

        # TODO: why do we need distinct
        return PackageV2.objects.filter(**filter_dict).distinct()

    def get_or_create_from_purl(self, purl: Union[PackageURL, str]):
        """
        Return a new or existing Package given a ``purl`` PackageURL object or PURL string.
        """
        package, is_created = PackageV2.objects.get_or_create(**purl_to_dict(purl=purl))

        return package, is_created

    def bulk_get_or_create_from_purls(self, purls: List[Union[PackageURL, str]]):
        """Return queryset of Packages for a list of PURLs, bulk create any that do not already exist."""

        packages_to_create = []
        normalize_purls = []

        for purl in purls:
            purl_dict = purl_to_dict(purl)
            purl = PackageURL(**purl_dict)

            normalized = normalize_purl(purl=purl)
            for name, value in purl_to_dict(normalized).items():
                setattr(self, name, value)

            purl_dict["package_url"] = str(normalized)
            purl_dict["plain_package_url"] = str(utils.plain_purl(normalized))

            normalize_purls.append(str(normalized))
            packages_to_create.append(PackageV2(**purl_dict))

        try:
            PackageV2.objects.bulk_create(packages_to_create, ignore_conflicts=True)
        except Exception as e:
            logging.error(f"Error creating PackageV2: {e} \n {traceback_format_exc()}")
            return []

        return PackageV2.objects.filter(package_url__in=normalize_purls)

    def only_vulnerable(self):
        return self._vulnerable()

    def for_purl(self, purl):
        """
        Return a queryset matching the ``purl`` Package URL.
        """
        return self.filter(package_url=purl)

    def for_purls(self, purls=()):
        """
        Return a queryset of Packages matching a list of PURLs.
        """
        return self.filter(package_url__in=purls).distinct()

    def _vulnerable(self):
        """
        Filter to select only vulnerable or non-vulnerable packages.
        """
        return self.with_is_vulnerable().filter(is_vulnerable=True)

    def _not_vulnerable(self):
        """
        Filter to select only vulnerable or non-vulnerable packages.
        """
        return self.with_is_not_vulnerable().filter(is_not_vulnerable=True)

    def with_is_vulnerable(self):
        """
        Annotate Package with ``is_vulnerable`` boolean attribute.
        """
        return self.annotate(
            is_vulnerable=Exists(
                ImpactedPackageAffecting.objects.filter(
                    package__pk=OuterRef("pk"),
                    impacted_package__advisory__is_latest=True,
                    impacted_package__advisory___all_impacts_unfurled_at__isnull=False,
                )
            )
        )

    def all_vulnerable(self):
        latest_unfurled_impacts = ImpactedPackageAffecting.objects.filter(
            package_id=OuterRef("pk"),
            impacted_package__advisory__is_latest=True,
            impacted_package__advisory___all_impacts_unfurled_at__isnull=False,
        )

        query = PackageV2.objects.filter(Exists(latest_unfurled_impacts))
        return query

    def all_vulnerable_purls(self):
        return self.all_vulnerable().values_list("package_url", flat=True)

    def filter_plain_purls(self, plain_purls=[]):
        return PackageV2.objects.filter(plain_package_url__in=plain_purls)

    def filter_purls(self, purls=[]):
        return PackageV2.objects.filter(package_url__in=purls)

    def from_purl(self, purl: Union[PackageURL, str]):
        """
        Return a new Package given a ``purl`` PackageURL object or PURL string.
        """
        package, _ = PackageV2.objects.get_or_create(**purl_to_dict(purl=purl))
        return package


class PackageV2(PackageURLMixin):
    """
    A software package with related vulnerabilities.
    """

    package_url = models.CharField(
        max_length=1000,
        null=False,
        help_text="The Package URL for this package.",
        db_index=True,
        unique=True,
    )

    plain_package_url = models.CharField(
        max_length=1000,
        null=False,
        help_text="The Package URL for this package without qualifiers and subpath.",
        db_index=True,
    )

    is_ghost = models.BooleanField(
        default=False,
        help_text="True if the package does not exist in the upstream package manager or its repository.",
        db_index=True,
    )

    risk_score = models.DecimalField(
        null=True,
        max_digits=3,
        decimal_places=1,
        help_text="Risk score between 0.00 and 10.00, where higher values "
        "indicate greater vulnerability risk for the package.",
    )

    version_rank = models.IntegerField(
        help_text="Rank of the version to support ordering by version. Rank "
        "zero means the rank has not been defined yet",
        default=0,
        db_index=True,
    )

    class Meta:
        unique_together = ["type", "namespace", "name", "version", "qualifiers", "subpath"]
        ordering = ["type", "namespace", "name", "version_rank", "version", "qualifiers", "subpath"]
        indexes = [
            # Index for getting al versions of a package
            models.Index(fields=["type", "namespace", "name"]),
            models.Index(fields=["type", "namespace", "name", "qualifiers", "subpath"]),
            # Index for getting a specific version of a package
            models.Index(
                fields=[
                    "type",
                    "namespace",
                    "name",
                    "version",
                ]
            ),
        ]

    def __str__(self):
        return self.package_url

    @property
    def purl(self):
        return self.package_url

    def save(self, *args, **kwargs):
        """
        Save, normalizing PURL fields.
        """
        purl = PackageURL(
            type=self.type,
            namespace=self.namespace,
            name=self.name,
            version=self.version,
            qualifiers=self.qualifiers,
            subpath=self.subpath,
        )

        # We re-parse the purl to ensure name and namespace
        # are set correctly
        normalized = normalize_purl(purl=purl)

        for name, value in purl_to_dict(normalized).items():
            setattr(self, name, value)

        self.package_url = str(normalized)
        plain_purl = utils.plain_purl(normalized)
        self.plain_package_url = str(plain_purl)
        super().save(*args, **kwargs)

    objects = PackageQuerySetV2.as_manager()

    @property
    def calculate_version_rank(self):
        """
        Calculate and return the `version_rank` for a package that does not have one.
        If this package already has a `version_rank`, return it.

        The calculated rank will be interpolated between two packages that have
        `version_rank` values and are closest to this package in terms of version order.
        """

        group_packages = PackageV2.objects.filter(
            type=self.type,
            namespace=self.namespace,
            name=self.name,
        )

        if any(p.version_rank == 0 for p in group_packages):
            sorted_packages = sorted(group_packages, key=lambda p: self.version_class(p.version))
            for rank, package in enumerate(sorted_packages, start=1):
                package.version_rank = rank
            PackageV2.objects.bulk_update(sorted_packages, fields=["version_rank"])
        return self.version_rank

    @cached_property
    def get_non_vulnerable_versions(self):
        """
        Cached computation to avoid duplicate queries.
        Returns (next, latest)
        """
        if self.version_rank == 0:
            self.calculate_version_rank

        evaluated = Exists(
            ImpactedPackageFixedBy.objects.filter(
                package_id=OuterRef("pk"),
                impacted_package__advisory__is_latest=True,
                impacted_package__advisory___all_impacts_unfurled_at__isnull=False,
            )
        )
        vulnerable = Exists(
            ImpactedPackageAffecting.objects.filter(
                package_id=OuterRef("pk"),
                impacted_package__advisory__is_latest=True,
                impacted_package__advisory___all_impacts_unfurled_at__isnull=False,
            )
        )

        qs = (
            PackageV2.objects.get_fixed_by_package_versions(self, fix=False)
            .annotate(evaluated=evaluated, vulnerable=vulnerable)
            .filter(evaluated=True, vulnerable=False, is_ghost=False)
            .filter(version_rank__gt=self.version_rank)
            .order_by("version_rank")
        )

        next_non_vulnerable = qs.first()
        latest_non_vulnerable = qs.last()

        return next_non_vulnerable, latest_non_vulnerable

    @property
    def next_non_vulnerable_version(self):
        next_nv, _ = self.get_non_vulnerable_versions
        return next_nv if next_nv else None

    @property
    def latest_non_vulnerable_version(self):
        _, latest_nv = self.get_non_vulnerable_versions
        return latest_nv if latest_nv else None

    @cached_property
    def version_class(self):
        range_class = RANGE_CLASS_BY_SCHEMES.get(self.type)
        return range_class.version_class if range_class else Version

    def get_absolute_url(self):
        """
        Return this Vulnerability details absolute URL.
        """
        return reverse("package_details_v2", args=[self.purl])

    @cached_property
    def current_version(self):
        return self.version_class(self.version)


class ImpactedPackageAffecting(models.Model):
    impacted_package = models.ForeignKey(
        ImpactedPackage,
        on_delete=models.CASCADE,
    )
    package = models.ForeignKey(
        PackageV2,
        on_delete=models.CASCADE,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    class Meta:
        unique_together = ("impacted_package", "package")
        indexes = [
            models.Index(fields=["package", "impacted_package"]),
        ]


class ImpactedPackageFixedBy(models.Model):
    impacted_package = models.ForeignKey(
        ImpactedPackage,
        on_delete=models.CASCADE,
    )
    package = models.ForeignKey(
        PackageV2,
        on_delete=models.CASCADE,
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
    )

    class Meta:
        unique_together = ("impacted_package", "package")
        indexes = [
            models.Index(fields=["package", "impacted_package"]),
        ]


class AdvisoryExploit(models.Model):
    """
    A vulnerability exploit is code used to
    take advantage of a security flaw for unauthorized access or malicious activity.
    """

    advisory = models.ForeignKey(
        AdvisoryV2,
        related_name="exploits",
        on_delete=models.CASCADE,
    )

    date_added = models.DateField(
        null=True,
        blank=True,
        help_text="The date the vulnerability was added to an exploit catalog.",
    )

    description = models.TextField(
        null=True,
        blank=True,
        help_text="Description of the vulnerability in an exploit catalog, often a refinement of the original CVE description",
    )

    required_action = models.TextField(
        null=True,
        blank=True,
        help_text="The required action to address the vulnerability, typically to "
        "apply vendor updates or apply vendor mitigations or to discontinue use.",
    )

    due_date = models.DateField(
        null=True,
        blank=True,
        help_text="The date the required action is due, which applies"
        " to all USA federal civilian executive branch (FCEB) agencies, "
        "but all organizations are strongly encouraged to execute the required action",
    )

    notes = models.TextField(
        null=True,
        blank=True,
        help_text="Additional notes and resources about the vulnerability,"
        " often a URL to vendor instructions.",
    )

    known_ransomware_campaign_use = models.BooleanField(
        default=False,
        help_text="""Known' if this vulnerability is known to have been leveraged as part of a ransomware campaign; 
        or 'Unknown' if there is no confirmation that the vulnerability has been utilized for ransomware.""",
    )

    source_date_published = models.DateField(
        null=True, blank=True, help_text="The date that the exploit was published or disclosed."
    )

    exploit_type = models.TextField(
        null=True,
        blank=True,
        help_text="The type of the exploit as provided by the original upstream data source.",
    )

    platform = models.TextField(
        null=True,
        blank=True,
        help_text="The platform associated with the exploit as provided by the original upstream data source.",
    )

    source_date_updated = models.DateField(
        null=True,
        blank=True,
        help_text="The date the exploit was updated in the original upstream data source.",
    )

    data_source = models.TextField(
        null=True,
        blank=True,
        help_text="The source of the exploit information, such as CISA KEV, exploitdb, metaspoit, or others.",
    )

    source_url = models.URLField(
        null=True,
        blank=True,
        help_text="The URL to the exploit as provided in the original upstream data source.",
    )

    record_id = models.CharField(
        null=True,
        blank=True,
        max_length=255,
        help_text="The unique identifier for the exploit record in the original upstream data source, such as the CISA KEV ID or the exploitdb ID.",
    )

    @property
    def get_known_ransomware_campaign_use_type(self):
        return "Known" if self.known_ransomware_campaign_use else "Unknown"

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["advisory", "data_source", "record_id"],
                name="unique_advisory_exploit_source",
            )
        ]


class SSVC(models.Model):
    vector = models.CharField(max_length=255, help_text="The vector string representing the SSVC.")
    options = models.JSONField(help_text="A JSON object containing the SSVC options.")
    decision = models.CharField(max_length=255, help_text="The decision string for the SSVC.")
    related_advisories = models.ManyToManyField(
        AdvisoryV2,
        related_name="related_ssvcs",
        help_text="Advisories associated with this SSVC.",
    )
    source_advisory = models.ForeignKey(
        AdvisoryV2,
        on_delete=models.CASCADE,
        related_name="source_ssvcs",
        help_text="The advisory that was used to generate this SSVC decision.",
    )

    def __str__(self):
        return f"SSVC Decision: {self.vector} -> {self.decision}"

    class Meta:
        unique_together = ("vector", "source_advisory")


class Group(NamedTuple):
    """
    A Group of advisories that have been merged together based on their content and identifiers.
    """

    aliases: Set[AdvisoryAlias]
    primary: AdvisoryV2
    secondaries: List[AdvisoryV2]


class GroupedAdvisory(NamedTuple):
    """
    A GroupedAdvisory represents a single advisory that has been grouped with its aliases and related advisories.
    """

    aliases: Set[AdvisoryAlias]
    advisory: AdvisoryV2
    identifier: str
    weighted_severity: Optional[float]
    exploitability: Optional[float]
    risk_score: Optional[float]
    ssvc_trees: List[Dict]


class AdvisoryPOC(models.Model):
    """
    An AdvisoryPOC (Proof of Concept) demonstrating how a vulnerability related to an advisory can be exploited.
    """

    advisory = models.ForeignKey(
        "AdvisoryV2",
        related_name="pocs",
        on_delete=models.CASCADE,
    )

    created_at = models.DateTimeField(
        null=True, blank=True, help_text="The date and time when this POC was created."
    )

    updated_at = models.DateTimeField(
        null=True, blank=True, help_text="The date and time when this POC was last updated."
    )

    url = models.URLField(help_text="The URL of the PoC, such as a repository or resource link.")

    is_confirmed = models.BooleanField(
        default=False, help_text="Indicates whether this POC has been verified or confirmed."
    )
