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


class VulnerabilityQuerySet(BaseQuerySet):
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

    def for_package(self, package):
        """
        Return a queryset of Vulnerability related to ``package``.
        """
        return self.filter(packages=package)

    def for_purl(self, package):
        """
        Return a queryset of Vulnerability related to ``package``.
        """
        return self.filter(packages=package)

    def search(self, query):
        """
        Return a Vulnerability queryset searching for the ``query``.
        Make a best effort approach to search a vulnerability.
        """

        qs = self
        query = query and query.strip()
        if not query:
            return qs.none()

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
            vulnerable_package_count=Count(
                "packages", filter=Q(packagerelatedvulnerability__fix=False), distinct=True
            ),
            patched_package_count=Count(
                "packages", filter=Q(packagerelatedvulnerability__fix=True), distinct=True
            ),
        )


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
    def severities(self):
        """
        Return a queryset of VulnerabilitySeverity for this vulnerability.
        """
        return VulnerabilitySeverity.objects.filter(reference__in=self.references.all())

    @property
    def affected_packages(self):
        """
        Return a queryset of packages that are affected by this vulnerability.
        """
        return self.packages.affected()

    # legacy aliases
    vulnerable_packages = affected_packages

    @property
    def fixed_by_packages(self):
        """
        Return a queryset of packages that are fixing this vulnerability.
        """
        return self.packages.fixing()

    # legacy alias
    patched_packages = fixed_by_packages

    @property
    def get_aliases(self):
        """
        Return a queryset of all Aliases for this vulnerability.
        """
        return self.aliases.all()

    alias = get_aliases

    def get_absolute_url(self):
        """
        Return this Vulnerability details absolute URL.
        """
        return reverse("vulnerability_details", args=[self.vulnerability_id])

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

    reference_id = models.CharField(
        max_length=200,
        help_text="An optional reference ID, such as DSA-4465-1 when available",
        blank=True,
    )

    objects = VulnerabilityReferenceQuerySet.as_manager()

    class Meta:
        ordering = ["reference_id", "url"]

    def __str__(self):
        reference_id = f" {self.reference_id}" if self.reference_id else ""
        return f"{self.url}{reference_id}"

    @property
    def is_cpe(self):
        """
        Return Trueis this is a CPE reference.
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


def purl_to_dict(purl: PackageURL):
    """
    Return a dict of purl components suitable for use in a queryset.
    We need to have specific empty values for using in querysets because of our peculiar model structure.

    For example::
    >>> purl_to_dict(PackageURL.from_string("pkg:generic/postgres"))
    {'type': 'generic', 'namespace': '', 'name': 'postgres', 'version': '', 'qualifiers': {}, 'subpath': ''}
    >>> purl_to_dict(PackageURL.from_string("pkg:generic/postgres/postgres@1.2?foo=bar#baz"))
    {'type': 'generic', 'namespace': 'postgres', 'name': 'postgres', 'version': '1.2', 'qualifiers': {'foo': 'bar'}, 'subpath': 'baz'}
    """
    if isinstance(purl, str):
        purl = PackageURL.from_string(purl)

    return dict(
        type=purl.type,
        namespace=purl.namespace or "",
        name=purl.name,
        version=purl.version or "",
        qualifiers=purl.qualifiers or {},
        subpath=purl.subpath or "",
    )


class PackageQuerySet(BaseQuerySet, PackageURLQuerySet):
    def get_or_create_from_purl(self, purl: PackageURL):
        """
        Return an existing or new Package (created if neeed) given a
        ``purl`` PackageURL.
        """
        if isinstance(purl, str):
            purl = PackageURL.from_string(purl)

        package, _ = Package.objects.get_or_create(**purl_to_dict(purl=purl))
        return package

    def for_package_url_object(self, purl):
        """
        Filter the QuerySet with the provided Package URL object or string. The
        ``purl`` string is validated and transformed into filtering lookups. If
        this is a PackageURL object it is reused as-is.
        """
        if not purl:
            return self.none()
        if isinstance(purl, str):
            purl = PackageURL.from_string(purl)
        lookups = without_empty_values(purl.to_dict(encode=True))
        return self.filter(**lookups)

    def affected(self):
        """
        Return only packages affected by a vulnerability.
        """
        return self.filter(packagerelatedvulnerability__fix=False)

    vulnerable = affected

    def fixing(self):
        """
        Return only packages fixing a vulnerability .
        """
        return self.filter(packagerelatedvulnerability__fix=True)

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

    def fixing_packages(self, package, with_qualifiers_and_subpath=True):
        """
        Return a queryset of packages that are fixing the vulnerability of
        ``package``.
        """

        return self.match_purl(
            purl=package.purl,
            with_qualifiers_and_subpath=with_qualifiers_and_subpath,
        ).fixing()

    def search(self, query=None):
        """
        Return a Package queryset searching for the ``query``.
        Make a best effort approach to find matching packages either based
        on exact purl, partial purl or just name and namespace.
        """
        query = query and query.strip()
        if not query:
            return self.none()

        qs = self
        if not query.startswith("pkg:"):
            # treat this as a plain search
            qs = qs.filter(Q(name__icontains=query) | Q(namespace__icontains=query))
        else:
            # this looks like a purl: check if it quacks like a purl
            purl_type = namespace = name = version = None

            _, _scheme, remainder = query.partition("pkg:")
            remainder = remainder.strip()
            if not remainder:
                return qs.none()

            try:
                # First, treat the query as a syntactically-correct purl
                purl = PackageURL.from_string(query)
                purl_type, namespace, name, version, _quals, _subp = purl.to_dict().values()
            except ValueError:
                # Otherwise, attempt a more lenient parsing of a possibly partial purl
                if "/" in remainder:
                    purl_type, _scheme, ns_name = remainder.partition("/")
                    ns_name = ns_name.strip()
                    if ns_name:
                        if "/" in ns_name:
                            namespace, _, name = ns_name.partition("/")
                        else:
                            name = ns_name
                        name = name.strip()
                        if name:
                            if "@" in name:
                                name, _, version = name.partition("@")
                                version = version.strip()
                                name = name.strip()
                else:
                    purl_type = remainder

            if purl_type:
                qs = qs.filter(type__iexact=purl_type)
            if namespace:
                qs = qs.filter(namespace__iexact=namespace)
            if name:
                qs = qs.filter(name__iexact=name)
            if version:
                qs = qs.filter(version__iexact=version)

        return qs

    def for_purl(self, purl, with_qualifiers_and_subpath=True):
        """
        Return a queryset matching the ``purl`` Package URL.
        """
        if not isinstance(purl, PackageURL):
            purl = PackageURL.from_string(purl)
        purl = purl.to_dict()
        if not with_qualifiers_and_subpath:
            del purl["qualifiers"]
            del purl["subpath"]
        return self.filter(**purl)

    def with_cpes(self):
        """
        Return a queryset of Package that a vulnerability with one or more NVD CPE references.
        """
        return self.filter(vulnerabilities__vulnerabilityreference__reference_id__startswith="cpe")

    def for_cpe(self, cpe):
        """
        Return a queryset of Vulnerability that have the ``cpe`` as an NVD CPE reference.
        """
        return self.filter(vulnerabilities__vulnerabilityreference__reference_id__exact=cpe)

    def with_cves(self):
        """
        Return a queryset of Vulnerability that have one or more NVD CVE aliases.
        """
        return self.filter(vulnerabilities__aliases__alias__startswith="CVE")

    def for_cve(self, cve):
        """
        Return a queryset of Vulnerability that have the the NVD CVE ``cve`` as an alias.
        """
        return self.filter(vulnerabilities__vulnerabilityreference__reference_id__exact=cve)


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

    objects = PackageQuerySet.as_manager()

    def save(self, *args, **kwargs):
        purl_object = PackageURL(
            type=self.type,
            namespace=self.namespace,
            name=self.name,
            version=self.version,
            qualifiers=self.qualifiers,
            subpath=self.subpath,
        )
        plain_purl = PackageURL(
            type=self.type,
            namespace=self.namespace,
            name=self.name,
            version=self.version,
        )
        self.package_url = str(purl_object)
        self.plain_package_url = str(plain_purl)
        super().save(*args, **kwargs)

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
    def affected_by(self):
        """
        Return a queryset of vulnerabilities affecting this package.
        """
        return self.vulnerabilities.filter(packagerelatedvulnerability__fix=False)

    # legacy aliases
    vulnerable_to = affected_by

    @property
    # TODO: consider renaming to "fixes" or "fixing" ? (TBD) and updating the docstring
    def fixing(self):
        """
        Return a queryset of vulnerabilities fixed by this package.
        """
        return self.vulnerabilities.filter(packagerelatedvulnerability__fix=True)

    # legacy aliases
    resolved_to = fixing

    @property
    def fixed_packages(self):
        """
        Return a queryset of packages that are fixed.
        """
        return Package.objects.fixing_packages(package=self).distinct()

    @property
    def is_vulnerable(self) -> bool:
        """
        Returns True if this package is vulnerable to any vulnerability.
        """
        return self.affected_by.exists()

    def get_absolute_url(self):
        """
        Return this Package details URL.
        """
        return reverse("package_details", args=[self.purl])


class PackageRelatedVulnerability(models.Model):
    """
    Track the relationship between a Package and Vulnerability.
    """

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

    class Meta:
        unique_together = ["reference", "scoring_system", "value"]
        ordering = ["reference", "scoring_system", "value"]


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
        help_text="An alias is a unique vulnerability identifier in some database, "
        "such as CVE-2020-2233",
    )

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name="aliases",
    )

    objects = AliasQuerySet.as_manager()

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
