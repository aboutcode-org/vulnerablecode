#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import hashlib
import json
import logging
from contextlib import suppress

from django.contrib.auth import get_user_model
from django.contrib.auth.models import UserManager
from django.core import exceptions
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator
from django.core.validators import MinValueValidator
from django.db import models
from django.db.models import Count
from django.db.models import Q
from django.db.models.functions import Length
from django.db.models.functions import Trim
from django.urls import reverse
from packageurl import PackageURL
from packageurl.contrib.django.models import PackageURLMixin
from packageurl.contrib.django.models import PackageURLQuerySet
from packageurl.contrib.django.models import without_empty_values
from rest_framework.authtoken.models import Token

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import build_vcid

logger = logging.getLogger(__name__)

models.CharField.register_lookup(Length)
models.CharField.register_lookup(Trim)


class BaseQuerySet(models.QuerySet):
    def get_or_none(self, *args, **kwargs):
        """
        Returns a single object matching the given keyword arguments, `None` otherwise.
        """
        with suppress(self.model.DoesNotExist, ValidationError):
            return self.get(*args, **kwargs)


class Vulnerability(models.Model):
    """
    A software vulnerability with a unique identifier and alternate ``aliases``.
    """

    vulnerability_id = models.CharField(
        unique=True,
        blank=True,
        max_length=20,
        default=build_vcid,
        help_text="Unique identifier for a vulnerability in the external representation. "
        "It is prefixed with VCID-",
    )

    summary = models.TextField(
        help_text="Summary of the vulnerability",
        blank=True,
    )

    references = models.ManyToManyField(
        to="VulnerabilityReference", through="VulnerabilityRelatedReference"
    )

    packages = models.ManyToManyField(
        to="Package",
        through="PackageRelatedVulnerability",
    )

    class Meta:
        verbose_name_plural = "Vulnerabilities"
        ordering = ["vulnerability_id"]

    def __str__(self):
        return self.vulnerability_id

    @property
    def severities(self):
        return VulnerabilitySeverity.objects.filter(reference__in=self.references.all())

    @property
    def vulnerable_to(self):
        """
        Return packages that are vulnerable to this vulnerability.
        """
        return self.packages.vulnerable()

    @property
    def resolved_to(self):
        """
        Returns packages that first received patch against this vulnerability
        in their particular version history.
        """
        return self.packages.filter(packagerelatedvulnerability__fix=True)

    @property
    def alias(self):
        """
        Returns packages that first received patch against this vulnerability
        in their particular version history.
        """
        return self.aliases.all()

    def get_absolute_url(self):
        """
        Return this Vulnerability details URL.
        """
        return reverse("vulnerability_details", args=[self.vulnerability_id])


class VulnerabilityReference(models.Model):
    """
    A reference to a vulnerability such as a security advisory from a Linux distribution or language
    package manager.
    """

    vulnerabilities = models.ManyToManyField(
        to="Vulnerability",
        through="VulnerabilityRelatedReference",
    )

    url = models.URLField(
        max_length=1024,
        help_text="URL to the vulnerability reference",
        unique=True,
    )

    reference_id = models.CharField(
        max_length=200,
        help_text="An optional reference ID, such as DSA-4465-1 when available",
        blank=True,
    )

    objects = BaseQuerySet.as_manager()

    class Meta:
        ordering = ["reference_id", "url"]

    def __str__(self):
        reference_id = f" {self.reference_id}" if self.reference_id else ""
        return f"{self.url}{reference_id}"


class VulnerabilityRelatedReference(models.Model):
    """
    A reference related to a vulnerability.
    """

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
    )

    reference = models.ForeignKey(
        VulnerabilityReference,
        on_delete=models.CASCADE,
    )

    class Meta:
        unique_together = ["vulnerability", "reference"]
        ordering = ["vulnerability", "reference"]


class PackageQuerySet(BaseQuerySet, PackageURLQuerySet):
    def get_or_create_from_purl(self, purl: PackageURL):
        """
        Return an existing or new Package (created if neeed) given a
        ``purl`` PackageURL.
        """
        purl_fields = without_empty_values(purl.to_dict(encode=True))
        package, _ = Package.objects.get_or_create(**purl_fields)
        return package

    def for_package_url_object(self, purl):
        """
        Filter the QuerySet with the provided Package URL object or string. The
        ``purl`` string is validated and transformed into filtering lookups. If
        this is a PackageURL object it is reused as-is.
        """
        if isinstance(purl, PackageURL):
            lookups = without_empty_values(purl.to_dict(encode=True))
            return self.filter(**lookups)

        elif isinstance(purl, str):
            return self.for_package_url(purl, encode=False)

        else:
            return self.none()

    def vulnerable(self):
        """
        Return all vulnerable packages.
        """
        return self.filter(packagerelatedvulnerability__fix=False)

    def with_vulnerability_counts(self):
        return self.annotate(
            vulnerability_count=Count(
                "vulnerabilities",
                filter=Q(packagerelatedvulnerability__fix=False),
            ),
            patched_vulnerability_count=Count(
                "vulnerabilities",
                filter=Q(packagerelatedvulnerability__fix=True),
            ),
        )


def get_purl_query_lookups(purl):
    """
    Do not reference all the possible qualifiers and relax the
    purl matching to only lookup the type, namespace, name and version fields.
    """
    lookup_fields = ["type", "namespace", "name", "version"]
    return {
        field_name: value
        for field_name, value in purl.to_dict().items()
        if value and field_name in lookup_fields
    }


class Package(PackageURLMixin):
    """
    A software package with related vulnerabilities.
    """

    # Remove the `qualifers` and `set_package_url` overrides after
    # https://github.com/package-url/packageurl-python/pull/35
    # https://github.com/package-url/packageurl-python/pull/67
    # gets merged
    qualifiers = models.JSONField(
        default=dict,
        help_text="Extra qualifying data for a package such as the name of an OS, "
        "architecture, distro, etc.",
        blank=True,
        null=False,
    )

    vulnerabilities = models.ManyToManyField(
        to="Vulnerability", through="PackageRelatedVulnerability"
    )

    objects = PackageQuerySet.as_manager()

    @property
    def purl(self):
        return self.package_url

    class Meta:
        unique_together = ["type", "namespace", "name", "version", "qualifiers", "subpath"]
        ordering = ["type", "namespace", "name", "version", "qualifiers", "subpath"]

    def __str__(self):
        return self.package_url

    @property
    # TODO: consider renaming to "affected_by"
    def vulnerable_to(self):
        """
        Returns vulnerabilities which are affecting this package.
        """
        return self.vulnerabilities.filter(packagerelatedvulnerability__fix=False)

    @property
    # TODO: consider renaming to "fixes" or "fixing" ? (TBD) and updating the docstring
    def resolved_to(self):
        """
        Returns the vulnerabilities which this package is patched against.
        """
        return self.vulnerabilities.filter(packagerelatedvulnerability__fix=True)

    @property
    def fixed_packages(self):
        """
        Returns vulnerabilities which are affecting this package.
        """
        return Package.objects.filter(
            name=self.name,
            namespace=self.namespace,
            type=self.type,
            qualifiers=self.qualifiers,
            subpath=self.subpath,
            packagerelatedvulnerability__fix=True,
        ).distinct()

    @property
    def is_vulnerable(self):
        """
        Returns True if this package is vulnerable to any vulnerability.
        """
        return self.vulnerable_to.exists()

    def get_absolute_url(self):
        """
        Return this Package details URL.
        """
        return reverse("package_details", args=[self.purl])


class PackageRelatedVulnerability(models.Model):

    # TODO: Fix related_name
    package = models.ForeignKey(
        Package,
        on_delete=models.CASCADE,
    )

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
    )
    created_by = models.CharField(
        max_length=100,
        blank=True,
        help_text="Fully qualified name of the improver prefixed with the"
        "module name responsible for creating this relation. Eg:"
        "vulnerabilities.importers.nginx.NginxBasicImprover",
    )

    confidence = models.PositiveIntegerField(
        default=MAX_CONFIDENCE,
        validators=[MinValueValidator(0), MaxValueValidator(MAX_CONFIDENCE)],
        help_text="Confidence score for this relation",
    )

    fix = models.BooleanField(
        default=False,
        db_index=True,
        help_text="Does this relation fix the specified vulnerability ?",
    )

    class Meta:
        unique_together = ["package", "vulnerability"]
        verbose_name_plural = "PackageRelatedVulnerabilities"
        indexes = [models.Index(fields=["fix"])]
        ordering = ["package", "vulnerability"]

    def __str__(self):
        return f"{self.package.package_url} {self.vulnerability.vulnerability_id}"

    def update_or_create(self):
        """
        Update if supplied record has more confidence than existing record
        Create if doesn't exist
        """
        try:
            existing = PackageRelatedVulnerability.objects.get(
                vulnerability=self.vulnerability, package=self.package
            )
            if self.confidence > existing.confidence:
                existing.created_by = self.created_by
                existing.confidence = self.confidence
                existing.fix = self.fix
                existing.save()
                # TODO: later we want these to be part of a log field in the DB
                logger.info(
                    f"Confidence improved for {self.package} R {self.vulnerability}, "
                    f"new confidence: {self.confidence}"
                )

        except self.DoesNotExist:
            PackageRelatedVulnerability.objects.create(
                vulnerability=self.vulnerability,
                created_by=self.created_by,
                package=self.package,
                confidence=self.confidence,
                fix=self.fix,
            )
            logger.info(
                f"New relationship {self.package} R {self.vulnerability}, "
                f"fix: {self.fix}, confidence: {self.confidence}"
            )


class VulnerabilitySeverity(models.Model):

    reference = models.ForeignKey(VulnerabilityReference, on_delete=models.CASCADE)

    scoring_system_choices = tuple(
        (system.identifier, system.name) for system in SCORING_SYSTEMS.values()
    )

    scoring_system = models.CharField(
        max_length=50,
        choices=scoring_system_choices,
        help_text="Identifier for the scoring system used. Available choices are: {} ".format(
            ", ".join(
                f"{sid} is vulnerability_id for {sname} system"
                for sid, sname in scoring_system_choices
            )
        ),
    )

    value = models.CharField(max_length=50, help_text="Example: 9.0, Important, High")

    class Meta:
        unique_together = ["reference", "scoring_system", "value"]
        ordering = ["reference", "scoring_system", "value"]


class Alias(models.Model):
    """
    An alias is a unique vulnerability identifier in some database, such as
    the NVD, PYSEC, CVE or similar. These databases guarantee that these
    identifiers are unique within their namespace.
    An alias may also be used as a Reference. But in contrast with some
    Reference may not be an identifier for a single vulnerability, for instance,
    security advisories such as Debian security advisory reference various
    vulnerabilities.
    """

    alias = models.CharField(
        max_length=50,
        unique=True,
        help_text="An alias is a unique vulnerability identifier in some database, "
        "such as CVE-2020-2233",
    )

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name="aliases",
    )

    class Meta:
        ordering = ["alias"]

    def __str__(self):
        return self.alias

    @property
    def url(self):
        """
        Create a URL for the alias.
        """
        alias: str = self.alias
        if alias.startswith("CVE"):
            return f"https://nvd.nist.gov/vuln/detail/{alias}"

        if alias.startswith("GHSA"):
            return f"https://github.com/advisories/{alias}"


class Advisory(models.Model):
    """
    An advisory represents data directly obtained from upstream transformed
    into structured data
    """

    unique_content_id = models.CharField(
        max_length=32,
        blank=True,
    )
    aliases = models.JSONField(blank=True, default=list, help_text="A list of alias strings")
    summary = models.TextField(
        blank=True,
    )
    # we use a JSON field here to avoid creating a complete relational model for data that
    # is never queried directly; instead it is only retrieved and processed as a whole by
    # an improver
    affected_packages = models.JSONField(
        blank=True, default=list, help_text="A list of serializable AffectedPackage objects"
    )
    references = models.JSONField(
        blank=True, default=list, help_text="A list of serializable Reference objects"
    )
    date_published = models.DateTimeField(
        blank=True, null=True, help_text="UTC Date of publication of the advisory"
    )
    date_collected = models.DateTimeField(help_text="UTC Date on which the advisory was collected")
    date_improved = models.DateTimeField(
        blank=True,
        null=True,
        help_text="Latest date on which the advisory was improved by an improver",
    )
    created_by = models.CharField(
        max_length=100,
        help_text="Fully qualified name of the importer prefixed with the"
        "module name importing the advisory. Eg:"
        "vulnerabilities.importers.nginx.NginxImporter",
    )

    class Meta:
        unique_together = ["aliases", "unique_content_id", "date_published"]
        ordering = ["aliases", "date_published", "unique_content_id"]

    def save(self, *args, **kwargs):
        checksum = hashlib.md5()
        for field in (self.summary, self.affected_packages, self.references):
            value = json.dumps(field, separators=(",", ":")).encode("utf-8")
            checksum.update(value)
        self.unique_content_id = checksum.hexdigest()
        super().save(*args, **kwargs)

    def to_advisory_data(self) -> AdvisoryData:
        return AdvisoryData(
            aliases=self.aliases,
            summary=self.summary,
            affected_packages=[AffectedPackage.from_dict(pkg) for pkg in self.affected_packages],
            references=[Reference.from_dict(ref) for ref in self.references],
            date_published=self.date_published,
        )


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
    """
    A User proxy model to facilitate simplified admin API user creation.
    """

    objects = ApiUserManager()

    class Meta:
        proxy = True
