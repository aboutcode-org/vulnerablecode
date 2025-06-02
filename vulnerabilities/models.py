#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import csv
import datetime
import logging
import uuid
import xml.etree.ElementTree as ET
from contextlib import suppress
from functools import cached_property
from itertools import groupby
from operator import attrgetter
from typing import Union
from urllib.parse import urljoin

import django_rq
import redis
from cvss.exceptions import CVSS2MalformedError
from cvss.exceptions import CVSS3MalformedError
from cvss.exceptions import CVSS4MalformedError
from cwe2.database import Database
from cwe2.mappings import xml_database_path
from cwe2.weakness import Weakness as DBWeakness
from django.contrib.auth import get_user_model
from django.contrib.auth.models import UserManager
from django.core import exceptions
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.core.validators import MaxValueValidator
from django.core.validators import MinValueValidator
from django.db import models
from django.db import transaction
from django.db.models import Count
from django.db.models import Exists
from django.db.models import OuterRef
from django.db.models import Prefetch
from django.db.models import Q
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
from vulnerabilities.severity_systems import EPSS
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import normalize_purl
from vulnerabilities.utils import purl_to_dict
from vulnerablecode import __version__ as VULNERABLECODE_VERSION
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


class VulnerabilityQuerySet(BaseQuerySet):
    def affecting_vulnerabilities(self):
        """
        Return a queryset of Vulnerability that affect a package.
        """
        return self.filter(affecting_packages__isnull=False)

    def with_cpes(self):
        """
        Return a queryset of Vulnerability that have one or more NVD CPE references.
        """
        return self.filter(vulnerabilityreference__reference_id__startswith="cpe")

    def for_cpe(self, cpe):
        """
        Return a queryset of Vulnerability that have the ``cpe`` as an NVD CPE reference.
        """
        return self.filter(vulnerabilityreference__reference_id__exact=cpe)

    def with_cves(self):
        """
        Return a queryset of Vulnerability that have one or more NVD CVE aliases.
        """
        return self.filter(aliases__alias__startswith="CVE")

    def for_cve(self, cve):
        """
        Return a queryset of Vulnerability that have the the NVD CVE ``cve`` as an alias.
        """
        return self.filter(vulnerabilityreference__reference_id__exact=cve)

    def with_packages(self):
        """
        Return a queryset of Vulnerability that have one or more related packages.
        """
        return self.filter(packages__isnull=False)

    def search(self, query: str = None):
        """
        Return a Vulnerability queryset searching for the ``query``.
        Make a best effort approach to search a vulnerability using various heuristics.
        """

        query = query and query.strip()
        if not query:
            return self.none()

        qs = self

        # middle ground, exact on vulnerability_id
        qssearch = qs.filter(vulnerability_id=query)
        if not qssearch.exists():
            # middle ground, exact on alias
            qssearch = qs.filter(aliases__alias=query)
            if not qssearch.exists():
                # middle ground, slow enough
                qssearch = qs.filter(
                    Q(vulnerability_id__icontains=query) | Q(aliases__alias__icontains=query)
                )
                if not qssearch.exists():
                    # last resort super slow
                    qssearch = qs.filter(
                        Q(references__id__icontains=query) | Q(summary__icontains=query)
                    )

        return qssearch.order_by("vulnerability_id")

    def with_package_counts(self):
        return self.annotate(
            vulnerable_package_count=Count("affecting_packages", distinct=True),
            patched_package_count=Count("fixed_by_packages", distinct=True),
        )


class VulnerabilitySeverity(models.Model):
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

    value = models.CharField(max_length=50, help_text="Example: 9.0, Important, High")

    scoring_elements = models.CharField(
        max_length=150,
        null=True,
        help_text="Supporting scoring elements used to compute the score values. "
        "For example a CVSS vector string as used to compute a CVSS score.",
    )

    published_at = models.DateTimeField(
        blank=True, null=True, help_text="UTC Date of publication of the vulnerability severity"
    )

    objects = BaseQuerySet.as_manager()

    class Meta:
        ordering = ["url", "scoring_system", "value"]


class VulnerabilityStatusType(models.IntegerChoices):
    """List of vulnerability statuses."""

    PUBLISHED = 1, "Published"
    DISPUTED = 2, "Disputed"
    INVALID = 3, "Invalid"


class Vulnerability(models.Model):
    """
    A software vulnerability with a unique identifier and alternate ``aliases``.
    """

    vulnerability_id = models.CharField(
        unique=True,
        blank=True,
        max_length=20,
        default=utils.build_vcid,
        help_text="Unique identifier for a vulnerability in the external representation. "
        "It is prefixed with VCID-",
        db_index=True,
    )

    summary = models.TextField(
        help_text="Summary of the vulnerability",
        blank=True,
    )

    references = models.ManyToManyField(
        to="VulnerabilityReference", through="VulnerabilityRelatedReference"
    )

    affecting_packages = models.ManyToManyField(
        to="Package",
        through="AffectedByPackageRelatedVulnerability",
    )

    fixed_by_packages = models.ManyToManyField(
        to="Package",
        through="FixingPackageRelatedVulnerability",
        related_name="fixing_vulnerabilities",  # Unique related_name
    )

    status = models.IntegerField(
        choices=VulnerabilityStatusType.choices, default=VulnerabilityStatusType.PUBLISHED
    )

    severities = models.ManyToManyField(
        VulnerabilitySeverity,
        related_name="vulnerabilities",
    )

    exploitability = models.DecimalField(
        null=True,
        max_digits=2,
        decimal_places=1,
        help_text="Exploitability indicates the likelihood that a vulnerability in a software package could be used by malicious actors to compromise systems, "
        "applications, or networks. This metric is determined automatically based on the discovery of known exploits.",
    )

    weighted_severity = models.DecimalField(
        null=True,
        max_digits=3,
        decimal_places=1,
        help_text="Weighted severity is the highest value calculated by multiplying each severity by its corresponding weight, divided by 10.",
    )

    @property
    def risk_score(self):
        """
        Risk expressed as a number ranging from 0 to 10.
        Risk is calculated from weighted severity and exploitability values.
        It is the maximum value of (the weighted severity multiplied by its exploitability) or 10
        Risk = min(weighted severity * exploitability, 10)
        """
        if self.exploitability and self.weighted_severity:
            risk_score = min(float(self.exploitability * self.weighted_severity), 10.0)
            return round(risk_score, 1)

    objects = VulnerabilityQuerySet.as_manager()

    class Meta:
        verbose_name_plural = "Vulnerabilities"
        ordering = ["vulnerability_id"]

    def __str__(self):
        return self.vulnerability_id

    @property
    def vcid(self):
        return self.vulnerability_id

    @property
    def affected_packages(self):
        """
        Return a queryset of packages that are affected by this vulnerability.
        """
        return self.affecting_packages.with_is_vulnerable()

    @property
    def packages_fixing(self):
        """
        Return a queryset of packages that are fixing this vulnerability.
        """
        return self.fixed_by_packages

    # legacy aliases
    vulnerable_packages = affected_packages

    # legacy alias
    patched_packages = packages_fixing

    @property
    def get_aliases(self):
        """
        Return a queryset of all Aliases for this vulnerability.
        """
        return self.aliases.all()

    alias = get_aliases

    @property
    def get_status_label(self):
        label_by_status = {choice[0]: choice[1] for choice in VulnerabilityStatusType.choices}
        return label_by_status.get(self.status) or VulnerabilityStatusType.PUBLISHED.label

    @property
    def history(self):
        return self.changelog.all()

    def get_absolute_url(self):
        """
        Return this Vulnerability details absolute URL.
        """
        return reverse("vulnerability_details", args=[self.vulnerability_id])

    def get_details_url(self, request):
        """
        Return this Package details URL.
        """
        from rest_framework.reverse import reverse as reved

        return reved(
            "vulnerability_details",
            kwargs={"vulnerability_id": self.vulnerability_id},
            request=request,
        )

    def get_related_cpes(self):
        """
        Return a list of CPE strings of this vulnerability.
        """
        return list(self.references.for_cpe().values_list("reference_id", flat=True).distinct())

    def get_related_cves(self):
        """
        Return a list of aliases CVE strings of this vulnerability.
        """
        return list(self.aliases.for_cve().values_list("alias", flat=True).distinct())

    def get_affected_purls(self):
        """
        Return a list of purl strings affected by this vulnerability.
        """
        return [p.package_url for p in self.affected_packages.all()]

    def get_fixing_purls(self):
        """
        Return a list of purl strings fixing this vulnerability.
        """
        return [p.package_url for p in self.fixed_by_packages.all()]

    def get_related_purls(self):
        """
        Return a list of purl strings related to this vulnerability.
        """
        return [p.package_url for p in self.packages.distinct().all()]

    def aggregate_fixed_and_affected_packages(self):
        from vulnerabilities.utils import get_purl_version_class

        sorted_fixed_by_packages = self.fixed_by_packages.filter(is_ghost=False).order_by(
            "type", "namespace", "name", "qualifiers", "subpath"
        )

        if sorted_fixed_by_packages:
            sorted_fixed_by_packages.first().calculate_version_rank

        sorted_affected_packages = self.affected_packages.all()

        if sorted_affected_packages:
            sorted_affected_packages.first().calculate_version_rank

        grouped_fixed_by_packages = {
            key: list(group)
            for key, group in groupby(
                sorted_fixed_by_packages,
                key=attrgetter("type", "namespace", "name", "qualifiers", "subpath"),
            )
        }

        all_affected_fixed_by_matches = []

        for sorted_affected_package in sorted_affected_packages:
            affected_fixed_by_matches = {
                "affected_package": sorted_affected_package,
                "matched_fixed_by_packages": [],
            }

            # Build the key to find matching group
            key = (
                sorted_affected_package.type,
                sorted_affected_package.namespace,
                sorted_affected_package.name,
                sorted_affected_package.qualifiers,
                sorted_affected_package.subpath,
            )

            # Get matching group from pre-grouped fixed_by_packages
            matching_fixed_packages = grouped_fixed_by_packages.get(key, [])

            # Get version classes for comparison
            affected_version_class = get_purl_version_class(sorted_affected_package)
            affected_version = affected_version_class(sorted_affected_package.version)

            # Compare versions and filter valid matches
            matched_fixed_by_packages = [
                fixed_by_package.purl
                for fixed_by_package in matching_fixed_packages
                if get_purl_version_class(fixed_by_package)(fixed_by_package.version)
                > affected_version
            ]

            affected_fixed_by_matches["matched_fixed_by_packages"] = matched_fixed_by_packages
            all_affected_fixed_by_matches.append(affected_fixed_by_matches)
        return sorted_fixed_by_packages, sorted_affected_packages, all_affected_fixed_by_matches

    def get_severity_vectors_and_values(self):
        """
        Collect severity vectors and values, excluding EPSS scoring systems and handling errors gracefully.
        """
        severity_vectors = []
        severity_values = set()

        # Exclude EPSS scoring system
        base_severities = self.severities.exclude(scoring_system=EPSS.identifier)

        # QuerySet for severities with valid scoring_elements and scoring_system in SCORING_SYSTEMS
        valid_scoring_severities = base_severities.filter(
            scoring_elements__isnull=False, scoring_system__in=SCORING_SYSTEMS.keys()
        )

        for severity in valid_scoring_severities:
            try:
                vector_values = SCORING_SYSTEMS[severity.scoring_system].get(
                    severity.scoring_elements
                )
                if vector_values:
                    severity_vectors.append(vector_values)
            except (
                CVSS2MalformedError,
                CVSS3MalformedError,
                CVSS4MalformedError,
                NotImplementedError,
            ) as e:
                logging.error(f"CVSSMalformedError for {severity.scoring_elements}: {e}")

        valid_value_severities = base_severities.filter(value__isnull=False).exclude(value="")

        severity_values.update(valid_value_severities.values_list("value", flat=True))

        return severity_vectors, severity_values


def get_cwes(self):
    """Yield CWE Weakness objects"""
    for cwe_category in self.cwe_files:
        cwe_category.seek(0)
        reader = csv.DictReader(cwe_category)
        for row in reader:
            yield DBWeakness(*list(row.values())[0:-1])
    tree = ET.parse(xml_database_path)
    root = tree.getroot()
    for tag_num in [1, 2]:  # Categories , Views
        tag = root[tag_num]
        for child in tag:
            yield DBWeakness(
                *[
                    child.attrib["ID"],
                    child.attrib.get("Name"),
                    None,
                    child.attrib.get("Status"),
                    child[0].text,
                ]
            )


Database.get_cwes = get_cwes


class Weakness(models.Model):
    """
    A Common Weakness Enumeration model
    """

    cwe_id = models.IntegerField(help_text="CWE id")
    vulnerabilities = models.ManyToManyField(Vulnerability, related_name="weaknesses")

    cwe_by_id = {}

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


class VulnerabilityReferenceQuerySet(BaseQuerySet):
    def for_cpe(self):
        """
        Return a queryset of VulnerabilityReferences that are for a CPE.
        """
        return self.filter(reference_id__startswith="cpe")


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

    ADVISORY = "advisory"
    EXPLOIT = "exploit"
    MAILING_LIST = "mailing_list"
    BUG = "bug"
    OTHER = "other"

    REFERENCE_TYPES = [
        (ADVISORY, "Advisory"),
        (EXPLOIT, "Exploit"),
        (MAILING_LIST, "Mailing List"),
        (BUG, "Bug"),
        (OTHER, "Other"),
    ]

    reference_type = models.CharField(max_length=20, choices=REFERENCE_TYPES, blank=True)

    reference_id = models.CharField(
        max_length=200,
        help_text="An optional reference ID, such as DSA-4465-1 when available",
        blank=True,
        db_index=True,
    )

    objects = VulnerabilityReferenceQuerySet.as_manager()

    class Meta:
        ordering = ["reference_id", "url", "reference_type"]

    def __str__(self):
        reference_id = f" {self.reference_id}" if self.reference_id else ""
        return f"{self.url}{reference_id}"

    @property
    def is_cpe(self):
        """
        Return True if this is a CPE reference.
        """
        return self.reference_id.startswith("cpe")


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
            filter_dict["fixing_vulnerabilities__isnull"] = False

        # TODO: why do we need distinct
        return Package.objects.filter(**filter_dict).distinct()

    def get_or_create_from_purl(self, purl: Union[PackageURL, str]):
        """
        Return a new or existing Package given a ``purl`` PackageURL object or PURL string.
        """
        package, is_created = Package.objects.get_or_create(**purl_to_dict(purl=purl))

        return package, is_created

    def from_purl(self, purl: Union[PackageURL, str]):
        """
        Return a new Package given a ``purl`` PackageURL object or PURL string.
        """
        return Package.objects.create(**purl_to_dict(purl=purl))

    def affected(self):
        """
        Return only packages affected by a vulnerability.
        """
        return self.filter(affected_by_vulnerabilities__isnull=False)

    vulnerable = affected

    def fixing(self):
        """
        Return only packages fixing a vulnerability .
        """
        return self.filter(fixing_vulnerabilities__isnull=False)

    def with_vulnerability_counts(self):
        return self.annotate(
            vulnerability_count=Count(
                "affected_by_vulnerabilities",
            ),
            patched_vulnerability_count=Count(
                "fixing_vulnerabilities",
            ),
        )

    def fixing_packages(self, package, with_qualifiers_and_subpath=True):
        """
        Return a queryset of packages that are fixing the vulnerability of
        ``package``.
        """

        return self.match_purl(
            purl=package.purl,
            with_qualifiers_and_subpath=with_qualifiers_and_subpath,
        ).fixing()

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
        return qs.order_by("package_url")

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

    def with_cpes(self):
        """
        Return a queryset of Package that a vulnerability with one or more NVD CPE references.
        """
        return self.filter(vulnerabilities__vulnerabilityreference__reference_id__startswith="cpe")

    def for_cpe(self, cpe):
        """
        Return a queryset of Packages that have the ``cpe`` as an NVD CPE reference.
        """
        return self.filter(vulnerabilities__vulnerabilityreference__reference_id__exact=cpe)

    def with_cves(self):
        """
        Return a queryset of Packages that have one or more NVD CVE aliases.
        """
        return self.filter(vulnerabilities__aliases__alias__startswith="CVE")

    def for_cve(self, cve):
        """
        Return a queryset of Packages that have the NVD CVE ``cve`` as a vulnerability alias.
        """
        return self.filter(vulnerabilities__aliases__alias=cve)

    def with_is_vulnerable(self):
        """
        Annotate Package with ``is_vulnerable`` boolean attribute.
        """
        return self.annotate(
            is_vulnerable=Exists(
                AffectedByPackageRelatedVulnerability.objects.filter(
                    package=OuterRef("pk"),
                )
            )
        )

    def only_vulnerable(self):
        return self._vulnerable(True)

    def only_non_vulnerable(self):
        return self._vulnerable(False).filter(is_ghost=False)

    def _vulnerable(self, vulnerable=True):
        """
        Filter to select only vulnerable or non-vulnearble packages.
        """
        return self.with_is_vulnerable().filter(is_vulnerable=vulnerable)

    def vulnerable(self):
        """
        Return only packages that are vulnerable.
        """
        return self.filter(affected_by_vulnerabilities__isnull=False)


def get_purl_query_lookups(purl):
    """
    Return a dictionary of non-empty plain purl fields
    Do not reference all the possible qualifiers and relax the
    purl matching to only lookup the type, namespace, name and version fields.
    """
    plain_purl = utils.plain_purl(purl=purl)
    return purl_to_dict(plain_purl, with_empty=False)


class Package(PackageURLMixin):
    """
    A software package with related vulnerabilities.
    """

    # Remove the `qualifers` and `set_package_url` overrides after
    # https://github.com/package-url/packageurl-python/pull/35
    # https://github.com/package-url/packageurl-python/pull/67
    # gets merged

    affected_by_vulnerabilities = models.ManyToManyField(
        to="Vulnerability",
        through="AffectedByPackageRelatedVulnerability",
    )

    fixing_vulnerabilities = models.ManyToManyField(
        to="Vulnerability",
        through="FixingPackageRelatedVulnerability",
        related_name="fixed_by_packages",  # Unique related_name
    )

    package_url = models.CharField(
        max_length=1000,
        null=False,
        help_text="The Package URL for this package.",
        db_index=True,
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

    objects = PackageQuerySet.as_manager()

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

    @property
    def calculate_version_rank(self):
        """
        Calculate and return the `version_rank` for a package that does not have one.
        If this package already has a `version_rank`, return it.

        The calculated rank will be interpolated between two packages that have
        `version_rank` values and are closest to this package in terms of version order.
        """

        group_packages = Package.objects.filter(
            type=self.type,
            namespace=self.namespace,
            name=self.name,
        )

        if any(p.version_rank == 0 for p in group_packages):
            sorted_packages = sorted(group_packages, key=lambda p: self.version_class(p.version))
            for rank, package in enumerate(sorted_packages, start=1):
                package.version_rank = rank
            Package.objects.bulk_update(sorted_packages, fields=["version_rank"])
        return self.version_rank

    @property
    def affected_by(self):
        """
        Return a queryset of vulnerabilities affecting this package.
        """
        return self.affected_by_vulnerabilities.all()

    # legacy aliases
    vulnerable_to = affected_by

    @property
    # TODO: consider renaming to "fixes" or "fixing" ? (TBD) and updating the docstring
    def fixing(self):
        """
        Return a queryset of vulnerabilities fixed by this package.
        """
        return self.fixing_vulnerabilities.all()

    # legacy aliases
    resolved_to = fixing

    @property
    def fixed_packages(self):
        """
        Return a queryset of packages that are fixed.
        """
        return Package.objects.fixing_packages(package=self).distinct()

    @property
    def history(self):
        return self.changelog.all()

    def get_absolute_url(self):
        """
        Return this Package details URL.
        """
        return reverse("package_details", args=[self.purl])

    def get_details_url(self, request):
        """
        Return this Package details URL.
        """
        from rest_framework.reverse import reverse

        return reverse("package_details", kwargs={"purl": self.purl}, request=request)

    @cached_property
    def version_class(self):
        range_class = RANGE_CLASS_BY_SCHEMES.get(self.type)
        return range_class.version_class if range_class else Version

    @cached_property
    def current_version(self):
        return self.version_class(self.version)

    @property
    def next_non_vulnerable_version(self):
        """
        Return the version string of the next non-vulnerable package version.
        """
        next_non_vulnerable, _ = self.get_non_vulnerable_versions()
        return next_non_vulnerable.version if next_non_vulnerable else None

    @property
    def latest_non_vulnerable_version(self):
        """
        Return the version string of the latest non-vulnerable package version.
        """
        _, latest_non_vulnerable = self.get_non_vulnerable_versions()
        return latest_non_vulnerable.version if latest_non_vulnerable else None

    def get_non_vulnerable_versions(self):
        """
        Return a tuple of the next and latest non-vulnerable versions as Package instance.
        Return a tuple of (None, None) if there is no non-vulnerable version.
        """
        if self.version_rank == 0:
            self.calculate_version_rank
        non_vulnerable_versions = Package.objects.get_fixed_by_package_versions(
            self, fix=False
        ).only_non_vulnerable()

        later_non_vulnerable_versions = non_vulnerable_versions.filter(
            version_rank__gt=self.version_rank
        )

        later_non_vulnerable_versions = list(later_non_vulnerable_versions)

        if later_non_vulnerable_versions:
            sorted_versions = later_non_vulnerable_versions
            next_non_vulnerable = sorted_versions[0]
            latest_non_vulnerable = sorted_versions[-1]
            return next_non_vulnerable, latest_non_vulnerable

        return None, None

    @property
    def fixed_package_details(self):
        """
        Return a mapping of vulnerabilities that affect this package and the next and
        latest non-vulnerable versions.
        """
        package_details = {}
        package_details["purl"] = PackageURL.from_string(self.purl)

        next_non_vulnerable, latest_non_vulnerable = self.get_non_vulnerable_versions()
        package_details["next_non_vulnerable"] = next_non_vulnerable
        package_details["latest_non_vulnerable"] = latest_non_vulnerable

        package_details["vulnerabilities"] = self.get_affecting_vulnerabilities()

        return package_details

    def get_affecting_vulnerabilities(self):
        """
        Return a list of vulnerabilities that affect this package together with information regarding
        the versions that fix the vulnerabilities.
        """
        if self.version_rank == 0:
            self.calculate_version_rank
        package_details_vulns = []

        fixed_by_packages = Package.objects.get_fixed_by_package_versions(self, fix=True)

        package_vulnerabilities = self.affected_by_vulnerabilities.prefetch_related(
            Prefetch(
                "fixed_by_packages",
                queryset=fixed_by_packages,
                to_attr="fixed_packages",
            )
        )

        for vuln in package_vulnerabilities:
            package_details_vulns.append({"vulnerability": vuln})
            later_fixed_packages = []

            for fixed_pkg in vuln.fixed_packages:
                if fixed_pkg not in fixed_by_packages:
                    continue
                fixed_version = self.version_class(fixed_pkg.version)
                if fixed_version > self.current_version:
                    later_fixed_packages.append(fixed_pkg)

            next_fixed_package_vulns = []

            sort_fixed_by_packages_by_version = []
            if later_fixed_packages:
                sort_fixed_by_packages_by_version = sorted(
                    later_fixed_packages, key=lambda p: p.version_rank
                )

            fixed_by_pkgs = []

            for vuln_details in package_details_vulns:
                if vuln_details["vulnerability"] != vuln:
                    continue
                vuln_details["fixed_by_purl"] = []
                vuln_details["fixed_by_purl_vulnerabilities"] = []

                for fixed_by_pkg in sort_fixed_by_packages_by_version:
                    fixed_by_package_details = {}
                    fixed_by_purl = PackageURL.from_string(fixed_by_pkg.purl)
                    next_fixed_package_vulns = list(fixed_by_pkg.affected_by)

                    fixed_by_package_details["fixed_by_purl"] = fixed_by_purl
                    fixed_by_package_details[
                        "fixed_by_purl_vulnerabilities"
                    ] = next_fixed_package_vulns
                    fixed_by_pkgs.append(fixed_by_package_details)

                    vuln_details["fixed_by_package_details"] = fixed_by_pkgs

        return package_details_vulns

    @property
    def fixing_vulnerabilities(self):
        """
        Return a queryset of Vulnerabilities that are fixed by this package.
        """
        print("A")
        return self.fixed_by_vulnerabilities.all()

    @property
    def affecting_vulns(self):
        """
        Return a queryset of Vulnerabilities that affect this `package`.
        """
        fixed_by_packages = Package.objects.get_fixed_by_package_versions(self, fix=True)
        return self.affected_by_vulnerabilities.all().prefetch_related(
            Prefetch(
                "fixed_by_packages",
                queryset=fixed_by_packages,
                to_attr="fixed_packages",
            )
        )


class PackageRelatedVulnerabilityBase(models.Model):
    """
    Abstract base class for package-vulnerability relations.
    """

    package = models.ForeignKey(
        Package,
        on_delete=models.CASCADE,
        db_index=True,
        # related_name="%(class)s_set",  # Unique related_name per subclass
    )

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        db_index=True,
        # related_name="%(class)s_set",  # Unique related_name per subclass
    )

    created_by = models.CharField(
        max_length=100,
        blank=True,
        help_text=(
            "Fully qualified name of the improver prefixed with the module name "
            "responsible for creating this relation. Eg: vulnerabilities.importers.nginx.NginxBasicImprover"
        ),
    )

    from vulnerabilities.improver import MAX_CONFIDENCE

    confidence = models.PositiveIntegerField(
        default=MAX_CONFIDENCE,
        validators=[MinValueValidator(0), MaxValueValidator(MAX_CONFIDENCE)],
        help_text="Confidence score for this relation",
    )

    class Meta:
        abstract = True
        unique_together = ["package", "vulnerability"]
        ordering = ["package", "vulnerability"]

    def __str__(self):
        relation = "fixes" if isinstance(self, FixingPackageRelatedVulnerability) else "affected by"
        return f"{self.package.package_url} {relation} {self.vulnerability.vulnerability_id}"

    def update_or_create(self, advisory):
        """
        Update if supplied record has more confidence than existing record.
        Create if it doesn't exist.
        """
        model_class = self.__class__
        try:
            existing = model_class.objects.get(
                vulnerability=self.vulnerability, package=self.package
            )
            if self.confidence > existing.confidence:
                existing.created_by = self.created_by
                existing.confidence = self.confidence
                existing.save()
                logger.info(
                    f"Confidence improved for {self.package} R {self.vulnerability}, "
                    f"new confidence: {self.confidence}"
                )
            self.add_package_vulnerability_changelog(advisory=advisory)
        except model_class.DoesNotExist:
            model_class.objects.create(
                vulnerability=self.vulnerability,
                created_by=self.created_by,
                package=self.package,
                confidence=self.confidence,
            )

            logger.info(
                f"New relationship {self.package} R {self.vulnerability}, "
                f"confidence: {self.confidence}"
            )

            self.add_package_vulnerability_changelog(advisory=advisory)

    @transaction.atomic
    def add_package_vulnerability_changelog(self, advisory):
        from vulnerabilities.utils import get_importer_name

        importer_name = get_importer_name(advisory)
        if isinstance(self, FixingPackageRelatedVulnerability):
            change_logger = PackageChangeLog.log_fixing
        else:
            change_logger = PackageChangeLog.log_affected_by
        change_logger(
            package=self.package,
            importer=importer_name,
            source_url=advisory.url or None,
            related_vulnerability=str(self.vulnerability),
        )


class FixingPackageRelatedVulnerability(PackageRelatedVulnerabilityBase):
    class Meta(PackageRelatedVulnerabilityBase.Meta):
        verbose_name_plural = "Fixing Package Related Vulnerabilities"


class AffectedByPackageRelatedVulnerability(PackageRelatedVulnerabilityBase):

    severities = models.ManyToManyField(
        VulnerabilitySeverity,
        related_name="affected_package_vulnerability_relations",
    )

    objects = BaseQuerySet.as_manager()

    class Meta(PackageRelatedVulnerabilityBase.Meta):
        verbose_name_plural = "Affected By Package Related Vulnerabilities"


class AliasQuerySet(BaseQuerySet):
    def for_cve(self):
        """
        Return a queryset of Aliases that are for a CVE.
        """
        return self.filter(alias__startswith="CVE")


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
        blank=False,
        null=False,
        help_text="An alias is a unique vulnerability identifier in some database, "
        "such as CVE-2020-2233",
    )

    vulnerability = models.ForeignKey(
        Vulnerability,
        related_name="aliases",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )

    objects = AliasQuerySet.as_manager()

    class Meta:
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


class AdvisoryQuerySet(BaseQuerySet):
    pass


class Advisory(models.Model):
    """
    An advisory represents data directly obtained from upstream transformed
    into structured data
    """

    unique_content_id = models.CharField(
        max_length=64,
        blank=False,
        null=False,
        unique=True,
        help_text="A 64 character unique identifier for the content of the advisory since we use sha256 as hex",
    )
    aliases = models.ManyToManyField(
        Alias,
        through="AdvisoryRelatedAlias",
        related_name="advisories",
    )
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
    weaknesses = models.JSONField(blank=True, default=list, help_text="A list of CWE ids")
    date_collected = models.DateTimeField(help_text="UTC Date on which the advisory was collected")
    date_imported = models.DateTimeField(
        blank=True, null=True, help_text="UTC Date on which the advisory was imported"
    )
    created_by = models.CharField(
        max_length=100,
        help_text="Fully qualified name of the importer prefixed with the"
        "module name importing the advisory. Eg:"
        "vulnerabilities.pipeline.nginx_importer.NginxImporterPipeline",
    )
    url = models.URLField(
        blank=False,
        null=False,
        help_text="Link to the advisory on the upstream website",
    )

    objects = AdvisoryQuerySet.as_manager()

    class Meta:
        ordering = ["date_published", "unique_content_id"]

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)

    def to_advisory_data(self) -> "AdvisoryData":
        from vulnerabilities.importer import AdvisoryData
        from vulnerabilities.importer import AffectedPackage
        from vulnerabilities.importer import Reference

        return AdvisoryData(
            aliases=[item.alias for item in self.aliases.all()],
            summary=self.summary,
            affected_packages=[
                AffectedPackage.from_dict(pkg) for pkg in self.affected_packages if pkg
            ],
            references=[Reference.from_dict(ref) for ref in self.references],
            date_published=self.date_published,
            weaknesses=self.weaknesses,
            url=self.url,
        )


class AdvisoryRelatedAlias(models.Model):
    advisory = models.ForeignKey(
        Advisory,
        on_delete=models.CASCADE,
    )

    alias = models.ForeignKey(
        Alias,
        on_delete=models.CASCADE,
    )

    class Meta:
        unique_together = ("advisory", "alias")


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
    """
    A User proxy model to facilitate simplified admin API user creation.
    """

    objects = ApiUserManager()

    class Meta:
        proxy = True


class ChangeLog(models.Model):
    action_time = models.DateTimeField(
        # check if dates are actually UTC
        default=timezone.now,
        editable=False,
        help_text="Time of the change",
    )

    actor_name = models.CharField(
        max_length=100,
        help_text="Name of the actor: either a script or username for instance tgoel, NVDImporter or NginxImprover.",
    )

    action_type = models.PositiveSmallIntegerField(
        help_text="Action type such as: update, create. Possible values are defined in subclasses"
    )

    source_url = models.URLField(
        max_length=1024,
        help_text="URL to the source of this change",
        blank=True,
        null=True,
    )

    software_version = models.CharField(
        max_length=100,
        help_text="Version of the software at the time of change",
        blank=False,
        null=False,
    )

    @property
    def get_action_type_label(self):
        label_by_status = {
            choice_code: choice_label for choice_code, choice_label in self.ACTION_TYPE_CHOICES
        }
        return label_by_status.get(self.action_type)

    @property
    def get_iso_time(self):
        return self.action_time.isoformat()

    class Meta:
        abstract = True
        ordering = ("-action_time",)


class VulnerabilityHistoryManager(models.Manager):
    def get_for_object(self, vuln, **kwargs):
        return self.filter(
            vulnerability=vuln,
            **kwargs,
        )

    def log_action(
        self,
        vulnerability,
        action_type,
        actor_name,
        source_url,
    ):
        """
        Creates a History entry for a given `obj` on Addition, Change, and Deletion.
        We do not log addition for object that inherit the HistoryFieldsMixin since
        the `created_by` and `created_date` are already set on its model.
        """
        return self.model.objects.get_or_create(
            vulnerability=vulnerability,
            action_type=action_type,
            actor_name=actor_name,
            source_url=source_url,
            software_version=VULNERABLECODE_VERSION,
        )


class VulnerabilityChangeLog(ChangeLog):
    IMPORT = 1
    IMPROVE = 2

    ACTION_TYPE_CHOICES = (
        (IMPORT, "Import"),
        (IMPROVE, "Improve"),
    )

    vulnerability = models.ForeignKey(
        Vulnerability, on_delete=models.CASCADE, related_name="changelog"
    )

    action_type = models.PositiveSmallIntegerField(choices=ACTION_TYPE_CHOICES)

    objects = VulnerabilityHistoryManager()

    @classmethod
    def log_import(cls, vulnerability, importer, source_url):
        """
        Creates History entry on Addition.
        """
        return cls.objects.log_action(
            vulnerability=vulnerability,
            action_type=VulnerabilityChangeLog.IMPORT,
            actor_name=importer,
            source_url=source_url,
        )

    @classmethod
    def log_improve(cls, vulnerability, improver, source_url):
        """
        Creates History entry on Improvement.
        """
        return cls.objects.log_action(
            vulnerability=vulnerability,
            action_type=VulnerabilityChangeLog.IMPROVE,
            actor_name=improver,
            source_url=source_url,
        )


class PackageHistoryManager(models.Manager):
    def get_for_object(self, package, **kwargs):
        return self.filter(
            package=package,
            **kwargs,
        )

    def log_action(self, package, action_type, actor_name, source_url, related_vulnerability):
        """
        Creates a History entry for a given `obj` on Addition, Change, and Deletion.
        We do not log addition for object that inherit the HistoryFieldsMixin since
        the `created_by` and `created_date` are already set on its model.
        """
        return self.model.objects.get_or_create(
            package=package,
            action_type=action_type,
            actor_name=actor_name,
            source_url=source_url,
            related_vulnerability=related_vulnerability,
            software_version=VULNERABLECODE_VERSION,
        )


class PackageChangeLog(ChangeLog):
    AFFECTED_BY = 1
    FIXING = 2

    ACTION_TYPE_CHOICES = ((AFFECTED_BY, "Affected by"), (FIXING, "Fixing"))

    package = models.ForeignKey(Package, on_delete=models.CASCADE, related_name="changelog")

    # NOTES: We are not using foreign key because this is a log
    # that we want to persist in case the VCID is not any more.

    # TODO: We will change to foeign key in future once the models get stable
    related_vulnerability = models.CharField(
        max_length=1024,
        null=True,
        blank=True,
        help_text="VCID of the vulnerability related to this package",
    )

    action_type = models.PositiveSmallIntegerField(choices=ACTION_TYPE_CHOICES)

    objects = PackageHistoryManager()

    @classmethod
    def log_affected_by(cls, package, importer, source_url, related_vulnerability):
        """
        Creates History entry on Vulnerabilitty affects package.
        """
        return cls.objects.log_action(
            package=package,
            action_type=PackageChangeLog.AFFECTED_BY,
            actor_name=importer,
            source_url=source_url,
            related_vulnerability=related_vulnerability,
        )

    @classmethod
    def log_fixing(cls, package, importer, source_url, related_vulnerability):
        """
        Creates History entry on Vulnerability is fixed by package.
        """
        return cls.objects.log_action(
            package=package,
            action_type=PackageChangeLog.FIXING,
            actor_name=importer,
            source_url=source_url,
            related_vulnerability=related_vulnerability,
        )


class Exploit(models.Model):
    """
    A vulnerability exploit is code used to
    take advantage of a security flaw for unauthorized access or malicious activity.
    """

    vulnerability = models.ForeignKey(
        Vulnerability,
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

    @property
    def get_known_ransomware_campaign_use_type(self):
        return "Known" if self.known_ransomware_campaign_use else "Unknown"


class CodeChange(models.Model):
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
        "Package",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="codechanges",
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


class CodeFix(CodeChange):
    """
    A code fix is a code change that addresses a vulnerability and is associated:
    - with a specific affected package version
    - optionally with a specific fixing package version when it is known
    """

    affected_package_vulnerability = models.ForeignKey(
        "AffectedByPackageRelatedVulnerability",
        on_delete=models.CASCADE,
        related_name="code_fix",
        help_text="The affected package version to which this code fix applies.",
    )

    fixed_package_vulnerability = models.ForeignKey(
        "FixingPackageRelatedVulnerability",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="code_fix",
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
        db_index=True,
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
        with suppress(NoSuchJobError):
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
    def execution_time(self):
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

    def delete_run(self, delete_self=True):
        if job := self.job:
            job.delete()

        if delete_self:
            self.delete()

    def delete(self, *args, **kwargs):
        """
        Before deletion of the run instance, try to stop the run execution.
        """
        with suppress(redis.exceptions.ConnectionError, AttributeError):
            self.stop_run()

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

    live_logging = models.BooleanField(
        null=False,
        db_index=True,
        default=False,
        help_text=(
            "When enabled logs will be streamed live during pipeline execution. "
            "For legacy importers and improvers, logs are always made available only after execution completes."
        ),
    )

    run_interval = models.PositiveSmallIntegerField(
        validators=[
            MinValueValidator(1, message="Interval must be at least 1 day."),
            MaxValueValidator(365, message="Interval must be at most 365 days."),
        ],
        default=1,
        help_text=("Number of days to wait between run of this pipeline."),
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
            if existing.is_active != self.is_active or existing.run_interval != self.run_interval:
                self.schedule_work_id = self.create_new_job()
        self.full_clean()
        return super().save(*args, **kwargs)

    @property
    def pipeline_class(self):
        """Return the pipeline class."""
        from vulnerabilities.importers import IMPORTERS_REGISTRY
        from vulnerabilities.improvers import IMPROVERS_REGISTRY

        if self.pipeline_id in IMPROVERS_REGISTRY:
            return IMPROVERS_REGISTRY.get(self.pipeline_id)
        if self.pipeline_id in IMPORTERS_REGISTRY:
            return IMPORTERS_REGISTRY.get(self.pipeline_id)

    @property
    def description(self):
        """Return the pipeline class."""
        if self.pipeline_class:
            return self.pipeline_class.__doc__

    @property
    def all_runs(self):
        """Return all the previous run instances for this pipeline."""
        return self.pipelineruns.all()

    @property
    def latest_run(self):
        return self.pipelineruns.first() if self.pipelineruns.exists() else None

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
    def next_run_date(self):
        if not self.is_active:
            return

        current_date_time = datetime.datetime.now(tz=datetime.timezone.utc)
        if self.latest_run_date:
            next_execution = self.latest_run_date + datetime.timedelta(days=self.run_interval)
            if next_execution > current_date_time:
                return next_execution

        return current_date_time

    @property
    def status(self):
        if not self.is_active:
            return

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
