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
from typing import Any

from cwe2.database import Database
from django.core.paginator import Paginator
from django.contrib.admin.models import ADDITION
from django.contrib.admin.models import CHANGE
from django.contrib.admin.models import DELETION
from django.contrib.admin.models import LogEntry
from django.contrib.auth import get_user_model
from django.contrib.auth.models import UserManager
from django.contrib.contenttypes.models import ContentType
from django.core import exceptions
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator
from django.core.validators import MinValueValidator
from django.db import models
from django.db.models import Count
from django.db.models import Prefetch
from django.db.models import Q
from django.db.models.functions import Length
from django.db.models.functions import Trim
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from packageurl import PackageURL
from packageurl.contrib.django.models import PackageURLMixin
from packageurl.contrib.django.models import PackageURLQuerySet
from packageurl.contrib.django.models import without_empty_values
from rest_framework.authtoken.models import Token
from univers import versions
from univers.version_range import RANGE_CLASS_BY_SCHEMES

from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import build_vcid
from vulnerabilities.utils import remove_qualifiers_and_subpath
from vulnerablecode import __version__ as vulnerablecode_version

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
            for object in page.object_list:
                yield object


class VulnerabilityQuerySet(BaseQuerySet):
    def affecting_vulnerabilities(self):
        """
        Return a queryset of Vulnerability that affect a package.
        """
        return self.filter(packagerelatedvulnerability__fix=False)

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

    status = models.IntegerField(
        choices=VulnerabilityStatusType.choices, default=VulnerabilityStatusType.PUBLISHED
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

    @property
    def history(self):
        """
        Return a queryset of Vulnerability that have one or more related packages.
        """
        from vulnerabilities.importers import IMPORTERS_REGISTRY

        vuln_logs_qs = self.vulnerabilitychangelog_set.all()
        for log in vuln_logs_qs.filter(action_type=1).distinct():
            authority = IMPORTERS_REGISTRY[log.actor_name].importing_authority
            importer_name = IMPORTERS_REGISTRY[log.actor_name].importer_name
            yield {
                "date_published": log.supporting_data["date_published"]
                if log.supporting_data["date_published"]
                else None,
                "message": f"Advisory published by { authority }"
                if log.actor_name
                else "Published by unknown source",
                # "source" : ""
                "source": log.supporting_data["url"] if log.supporting_data["url"] else "No source",
                "package": "",
                "vulnerablecode_version": vulnerablecode_version,
                "first_import": "",
            }
            yield {
                "date_published": log.action_time.strftime("%d %B, %Y"),
                "message": f"Imported at Vulnerablecode by {authority}",
                "source": "",
                "package": "",
                "first_import": "",
                "vulnerablecode_version": vulnerablecode_version,
            }

        for log in vuln_logs_qs.filter(action_type=3):
            importer_name = IMPORTERS_REGISTRY[log.actor_name].importer_name
            conflict = False
            if vuln_logs_qs.filter(
                action_type=4,
                vulnerability=log.vulnerability,
                supporting_data__package=log.supporting_data["package"],
            ).exists():
                conflict = True
            message = ""
            if log.supporting_data["first_import"]:
                message = f"""{importer_name} reports <a href="/packages/{log.supporting_data["package"]}?search={ log.supporting_data["package"] }" target="_self">{ log.supporting_data["package"] }</a> is affected by this vulnerability"""
            else:
                if conflict:
                    message = "CONFLICT: " + message
                else:
                    message = f"""{importer_name} confirms <a href="/packages/{log.supporting_data["package"]}?search={ log.supporting_data["package"] }" target="_self">{ log.supporting_data["package"] }</a> is affected by this vulnerability"""
            yield {
                "date_published": log.action_time.strftime("%d %B, %Y"),
                "message": message,
                "source": log.supporting_data["url"] if log.supporting_data["url"] else "No source",
                "package": log.supporting_data["package"],
                "first_import": log.supporting_data["first_import"],
                "vulnerablecode_version": vulnerablecode_version,
            }

        for log in vuln_logs_qs.filter(action_type=4):
            importer_name = IMPORTERS_REGISTRY[log.actor_name].importer_name
            conflict = False
            if vuln_logs_qs.filter(
                action_type=3,
                actor_name=log.actor_name,
                vulnerability=log.vulnerability,
                supporting_data__package=log.supporting_data["package"],
            ).exists():
                conflict = True
            if log.supporting_data["first_import"]:
                message = f"""{importer_name} reports <a href="/packages/{log.supporting_data["package"]}?search={ log.supporting_data["package"] }" target="_self">{ log.supporting_data["package"] }</a> is fixing this vulnerability"""
            else:
                if conflict:
                    message = "CONFLICT: " + message
                else:
                    message = f"""{importer_name} confirms <a href="/packages/{log.supporting_data["package"]}?search={ log.supporting_data["package"] }" target="_self">{ log.supporting_data["package"] }</a> is fixing this vulnerability"""
            yield {
                "date_published": log.action_time.strftime("%d %B, %Y"),
                "message": message,
                "source": log.supporting_data["url"] if log.supporting_data["url"] else "No source",
                "package": log.supporting_data["package"],
                "first_import": log.supporting_data["first_import"],
                "vulnerablecode_version": vulnerablecode_version,
            }

    alias = get_aliases

    @property
    def get_status_label(self):
        label_by_status = {choice[0]: choice[1] for choice in VulnerabilityStatusType.choices}
        return label_by_status.get(self.status) or VulnerabilityStatusType.PUBLISHED.label

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


class Weakness(models.Model):
    """
    A Common Weakness Enumeration model
    """

    cwe_id = models.IntegerField(help_text="CWE id")
    vulnerabilities = models.ManyToManyField(Vulnerability, related_name="weaknesses")
    db = Database()

    @property
    def name(self):
        """Return the weakness's name."""
        weakness = self.db.get(self.cwe_id)
        return weakness.name

    @property
    def description(self):
        """Return the weakness's description."""
        weakness = self.db.get(self.cwe_id)
        return weakness.description


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
            filter_dict["packagerelatedvulnerability__fix"] = True

        return Package.objects.filter(**filter_dict).distinct()

    def get_or_create_from_purl(self, purl: PackageURL):
        """
        Return an existing or new Package (created if neeed) given a
        ``purl`` PackageURL.
        """
        if isinstance(purl, str):
            purl = PackageURL.from_string(purl)

        package, is_created = Package.objects.get_or_create(**purl_to_dict(purl=purl))

        return package, is_created

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

        try:
            # if it's a valid purl, use it as is
            purl = PackageURL.from_string(query)
            purl = str(remove_qualifiers_and_subpath(purl))
            return qs.filter(package_url__istartswith=purl)
        except ValueError:
            return qs.filter(package_url__icontains=query)

    def for_purl(self, purl, with_qualifiers_and_subpath=True):
        """
        Return a queryset matching the ``purl`` Package URL.
        """
        if not isinstance(purl, PackageURL):
            purl = PackageURL.from_string(purl)
        if not with_qualifiers_and_subpath:
            remove_qualifiers_and_subpath(purl)
        purl = purl_to_dict(purl)
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

    def for_purls(self, purls=[]):
        return Package.objects.filter(package_url__in=purls).distinct()


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
    def affected_by(self):
        """
        Return a queryset of vulnerabilities affecting this package.
        """
        return self.vulnerabilities.filter(packagerelatedvulnerability__fix=False)

    @property
    def history(self):
        """
        Return a queryset of vulnerabilities affecting this package.
        """
        from vulnerabilities.importers import IMPORTERS_REGISTRY

        vuln_logs_qs = self.packagechangelog_set.all()
        print(vuln_logs_qs)
        for log in vuln_logs_qs.filter(action_type=1).distinct():
            authority = IMPORTERS_REGISTRY[log.actor_name].importing_authority
            importer_name = IMPORTERS_REGISTRY[log.actor_name].importer_name
            yield {
                "date_published": log.supporting_data["date_published"]
                if log.supporting_data["date_published"]
                else None,
                "message": f"Advisory published by { authority }"
                if log.actor_name
                else "Published by unknown source",
                # "source" : ""
                "source": log.supporting_data["url"] if log.supporting_data["url"] else "No source",
                "package": "",
                "vulnerablecode_version": vulnerablecode_version,
                "first_import": "",
            }
            yield {
                "date_published": log.action_time.strftime("%d %B, %Y"),
                "message": f"Imported at Vulnerablecode by {authority}",
                "source": "",
                "package": "",
                "first_import": "",
                "vulnerablecode_version": vulnerablecode_version,
            }

        for log in vuln_logs_qs.filter(action_type=3):
            importer_name = IMPORTERS_REGISTRY[log.actor_name].importer_name
            conflict = False
            if vuln_logs_qs.filter(
                action_type=4,
                package=log.package,
                supporting_data__vulnerability=log.supporting_data["vulnerability"],
            ).exists():
                conflict = True
            message = ""
            if log.supporting_data["first_import"]:
                message = f"""{importer_name} reports <a href="/vulnerabilities/{log.supporting_data["vulnerability"]}?search={ log.supporting_data["vulnerability"] }" target="_self">{ log.supporting_data["vulnerability"] }</a> is affecting this package"""
            else:
                if conflict:
                    message = "CONFLICT: " + message
                else:
                    message = f"""{importer_name} confirms <a href="/vulnerabilities/{log.supporting_data["vulnerability"]}?search={ log.supporting_data["vulnerability"] }" target="_self">{ log.supporting_data["vulnerability"] }</a> is affecting this package"""
            yield {
                "date_published": log.action_time.strftime("%d %B, %Y"),
                "message": message,
                "source": log.supporting_data["url"] if log.supporting_data["url"] else "No source",
                "vulnerability": log.supporting_data["vulnerability"],
                "first_import": log.supporting_data["first_import"],
                "vulnerablecode_version": vulnerablecode_version,
            }

        for log in vuln_logs_qs.filter(action_type=4):
            importer_name = IMPORTERS_REGISTRY[log.actor_name].importer_name
            conflict = False
            if vuln_logs_qs.filter(
                action_type=3,
                actor_name=log.actor_name,
                package=log.package,
                supporting_data__vulnerability=log.supporting_data["vulnerability"],
            ).exists():
                conflict = True
            if log.supporting_data["first_import"]:
                message = f"""{importer_name} reports <a href="/vulnerabilties/{log.supporting_data["vulnerability"]}?search={ log.supporting_data["vulnerability"] }" target="_self">{ log.supporting_data["vulnerability"] }</a> is fixed by this package"""
            else:
                if conflict:
                    message = "CONFLICT: " + message
                else:
                    message = f"""{importer_name} confirms <a href="/vulnerabilities/{log.supporting_data["vulnerability"]}?search={ log.supporting_data["vulnerability"] }" target="_self">{ log.supporting_data["vulnerability"] }</a> is fixed by this package"""
            yield {
                "date_published": log.action_time.strftime("%d %B, %Y"),
                "message": message,
                "source": log.supporting_data["url"] if log.supporting_data["url"] else "No source",
                "vulnerability": log.supporting_data["vulnerability"],
                "first_import": log.supporting_data["first_import"],
                "vulnerablecode_version": vulnerablecode_version,
            }

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

    def sort_by_version(self, packages):
        """
        Return a list of `packages` sorted by version.
        """
        if not packages:
            return []

        return sorted(
            packages,
            key=lambda x: self.version_class(x.version),
        )

    @property
    def version_class(self):
        return RANGE_CLASS_BY_SCHEMES[self.type].version_class

    @property
    def current_version(self):
        return self.version_class(self.version)

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

    def get_non_vulnerable_versions(self):
        """
        Return a tuple of the next and latest non-vulnerable versions as PackageURLs.  Return a tuple of
        (None, None) if there is no non-vulnerable version.
        """
        package_versions = Package.objects.get_fixed_by_package_versions(self, fix=False)

        non_vulnerable_versions = []
        for version in package_versions:
            if not version.is_vulnerable:
                non_vulnerable_versions.append(version)

        later_non_vulnerable_versions = []
        for non_vuln_ver in non_vulnerable_versions:
            if self.version_class(non_vuln_ver.version) > self.current_version:
                later_non_vulnerable_versions.append(non_vuln_ver)

        if later_non_vulnerable_versions:
            sorted_versions = self.sort_by_version(later_non_vulnerable_versions)
            next_non_vulnerable_version = sorted_versions[0]
            latest_non_vulnerable_version = sorted_versions[-1]

            next_non_vulnerable = PackageURL.from_string(next_non_vulnerable_version.purl)
            latest_non_vulnerable = PackageURL.from_string(latest_non_vulnerable_version.purl)

            return next_non_vulnerable, latest_non_vulnerable

        return None, None

    def get_affecting_vulnerabilities(self):
        """
        Return a list of vulnerabilities that affect this package together with information regarding
        the versions that fix the vulnerabilities.
        """
        package_details_vulns = []

        fixed_by_packages = Package.objects.get_fixed_by_package_versions(self, fix=True)

        package_vulnerabilities = self.vulnerabilities.affecting_vulnerabilities().prefetch_related(
            Prefetch(
                "packages",
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

            next_fixed_package = None
            next_fixed_package_vulns = []

            sort_fixed_by_packages_by_version = []
            if later_fixed_packages:
                sort_fixed_by_packages_by_version = self.sort_by_version(later_fixed_packages)

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
        Return a queryset of Vulnerabilities that are fixed by this `package`.
        """
        return self.vulnerabilities.filter(packagerelatedvulnerability__fix=True)

    @property
    def affecting_vulnerabilities(self):
        """
        Return a queryset of Vulnerabilities that affect this `package`.
        """
        return self.vulnerabilities.filter(packagerelatedvulnerability__fix=False)


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
    from vulnerabilities.improver import MAX_CONFIDENCE

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

    def update_or_create(self, advisory):
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
            self.add_vulnerability_changelog(advisory, False)

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

            self.add_vulnerability_changelog(advisory, True)

    def add_vulnerability_changelog(self, advisory, first_import):
        if VulnerabilityChangeLog.objects.filter(
            vulnerability=self.vulnerability,
            actor_name=advisory.created_by,
            supporting_data__package=str(self.package),
        ).exists():
            return

        if self.fix:
            VulnerabilityChangeLog.log_fixed_by(
                vulnerability=self.vulnerability,
                importer=advisory.created_by,
                supporting_data={
                    "package": str(self.package),
                    "url": advisory.url if advisory.url else None,
                    "first_import": first_import,
                },
            )
            PackageChangeLog.log_fixing(
                package=self.package,
                importer=advisory.created_by,
                supporting_data={
                    "vulnerability": str(self.vulnerability),
                    "url": advisory.url if advisory.url else None,
                    "first_import": first_import,
                },
            )
        else:
            VulnerabilityChangeLog.log_affects(
                vulnerability=self.vulnerability,
                importer=advisory.created_by,
                supporting_data={
                    "package": str(self.package),
                    "url": advisory.url if advisory.url else None,
                    "first_import": first_import,
                },
            )

            PackageChangeLog.log_affected_by(
                package=self.package,
                importer=advisory.created_by,
                supporting_data={
                    "vulnerability": str(self.vulnerability),
                    "url": advisory.url if advisory.url else None,
                    "first_import": first_import,
                },
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
        blank=False,
        null=False,
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

        if alias.startswith("NPM-"):
            id = alias.lstrip("NPM-")
            return f"https://github.com/nodejs/security-wg/blob/main/vuln/npm/{id}.json"


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
    weaknesses = models.JSONField(blank=True, default=list, help_text="A list of CWE ids")
    date_collected = models.DateTimeField(help_text="UTC Date on which the advisory was collected")
    date_imported = models.DateTimeField(
        blank=True, null=True, help_text="UTC Date on which the advisory was imported"
    )
    created_by = models.CharField(
        max_length=100,
        help_text="Fully qualified name of the importer prefixed with the"
        "module name importing the advisory. Eg:"
        "vulnerabilities.importers.nginx.NginxImporter",
    )
    url = models.URLField(
        blank=True,
        help_text="Link to the advisory on the upstream website",
    )

    class Meta:
        unique_together = ["aliases", "unique_content_id", "date_published"]
        ordering = ["aliases", "date_published", "unique_content_id"]

    def save(self, *args, **kwargs):
        checksum = hashlib.md5()
        for field in (self.summary, self.affected_packages, self.references, self.weaknesses):
            value = json.dumps(field, separators=(",", ":")).encode("utf-8")
            checksum.update(value)
        self.unique_content_id = checksum.hexdigest()
        super().save(*args, **kwargs)

    def to_advisory_data(self) -> "AdvisoryData":
        from vulnerabilities.importer import AdvisoryData
        from vulnerabilities.importer import AffectedPackage
        from vulnerabilities.importer import Reference

        return AdvisoryData(
            aliases=self.aliases,
            summary=self.summary,
            affected_packages=[AffectedPackage.from_dict(pkg) for pkg in self.affected_packages],
            references=[Reference.from_dict(ref) for ref in self.references],
            date_published=self.date_published,
            weaknesses=self.weaknesses,
            url=self.url,
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


class HistoryManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().select_related(None)

    def get_for_object(self, vuln, **kwargs):
        return self.filter(
            vulnerability=vuln,
            **kwargs,
        )

    def log_action(self, improver, vulnerability, date_published, importer, advisory, message=""):
        """
        Creates a History entry for a given `obj` on Addition, Change, and Deletion.
        We do not log addition for object that inherit the HistoryFieldsMixin since
        the `created_by` and `created_date` are already set on its model.
        """
        if isinstance(message, list):
            message = json.dumps(message)

        return self.model.objects.get_or_create(
            date_published=date_published,
            importer=importer,
            vulnerability=vulnerability,
            advisory=advisory,
            # change_message=message,
        )


class ChangeLog(models.Model):

    action_time = models.DateTimeField(
        # check if dates are actually UTC
        default=timezone.now,
        editable=False,
        help_text="UTC Date of the change",
    )

    action_message = models.TextField(
        blank=True,
    )

    supporting_data = models.JSONField(
        blank=True,
        null=True,
        help_text="JSON representation of the advisory data",
    )

    actor_name = models.CharField(
        max_length=100,
        help_text="Name of the actor: NVDImporter, NginxImprover etc.",
    )

    vulnerablecode_version = models.CharField(
        max_length=100,
        help_text="Version of the vulnerablecode at the time of change",
        default=vulnerablecode_version,
    )

    objects = HistoryManager()

    @classmethod
    def log_change(cls, vulnerability, importer, date_published):
        """
        Creates History entry on Change.
        """
        return cls.objects.log_action(
            importer=importer,
            vulnerability=vulnerability,
            date_published=date_published,
        )

    class Meta:
        abstract = True


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
        supporting_data={},
        action_message="",
    ):
        """
        Creates a History entry for a given `obj` on Addition, Change, and Deletion.
        We do not log addition for object that inherit the HistoryFieldsMixin since
        the `created_by` and `created_date` are already set on its model.
        """
        if isinstance(action_message, list):
            action_message = json.dumps(action_message)

        return self.model.objects.get_or_create(
            vulnerability=vulnerability,
            action_type=action_type,
            actor_name=actor_name,
            supporting_data=supporting_data,
            action_message=action_message,
        )


class VulnerabilityChangeLog(ChangeLog):
    ACTION_TYPES = (
        (1, "Import"),
        (2, "Improve"),
        (3, "Affects"),
        (4, "Fixed By"),
    )

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
    )

    action_type = models.PositiveSmallIntegerField(
        choices=ACTION_TYPES,
    )

    objects = VulnerabilityHistoryManager()

    @classmethod
    def log_import(cls, vulnerability, importer, supporting_data={}):
        """
        Creates History entry on Addition.
        """
        return cls.objects.log_action(
            vulnerability=vulnerability,
            action_type=1,
            actor_name=importer,
            supporting_data=supporting_data,
        )

    @classmethod
    def log_improve(cls, vulnerability, improver):
        """
        Creates History entry on Improvement.
        """
        return cls.objects.log_action(
            vulnerability=vulnerability,
            action_type=2,
            actor_name=improver,
        )

    @classmethod
    def log_affects(cls, vulnerability, importer, supporting_data={}):
        """
        Creates History entry on Vulnerabilitty affects package.
        """
        return cls.objects.log_action(
            vulnerability=vulnerability,
            action_type=3,
            actor_name=importer,
            supporting_data=supporting_data,
        )

    @classmethod
    def log_fixed_by(cls, vulnerability, importer, supporting_data={}):
        """
        Creates History entry on Vulnerabilitty is fixed by package.
        """
        return cls.objects.log_action(
            vulnerability=vulnerability,
            action_type=4,
            actor_name=importer,
            supporting_data=supporting_data,
        )


class PackageHistoryManager(models.Manager):
    def get_for_object(self, vuln, **kwargs):
        return self.filter(
            vulnerability=vuln,
            **kwargs,
        )

    def log_action(
        self,
        package,
        action_type,
        actor_name,
        supporting_data={},
        action_message="",
    ):
        """
        Creates a History entry for a given `obj` on Addition, Change, and Deletion.
        We do not log addition for object that inherit the HistoryFieldsMixin since
        the `created_by` and `created_date` are already set on its model.
        """
        if isinstance(action_message, list):
            action_message = json.dumps(action_message)

        return self.model.objects.get_or_create(
            package=package,
            action_type=action_type,
            actor_name=actor_name,
            supporting_data=supporting_data,
            action_message=action_message,
        )


class PackageChangeLog(ChangeLog):
    ACTION_TYPES = (
        (1, "Import"),
        (2, "Improve"),
        (3, "Affected By"),
        (4, "Fixing"),
    )

    package = models.ForeignKey(
        Package,
        on_delete=models.CASCADE,
    )

    action_type = models.PositiveSmallIntegerField(
        choices=ACTION_TYPES,
    )

    objects = PackageHistoryManager()

    @classmethod
    def log_import(cls, package, importer, supporting_data={}):
        """
        Creates History entry on Addition.
        """
        print("PACKAGE IMPORTED")
        return cls.objects.log_action(
            package=package,
            action_type=1,
            actor_name=importer,
            supporting_data=supporting_data,
        )

    @classmethod
    def log_improve(cls, package, improver):
        """
        Creates History entry on Improvement.
        """
        return cls.objects.log_action(
            package=package,
            action_type=2,
            actor_name=improver,
        )

    @classmethod
    def log_affected_by(cls, package, importer, supporting_data={}):
        """
        Creates History entry on Vulnerabilitty affects package.
        """
        print("PACKAGE AFFECTED")
        return cls.objects.log_action(
            package=package,
            action_type=3,
            actor_name=importer,
            supporting_data=supporting_data,
        )

    @classmethod
    def log_fixing(cls, package, importer, supporting_data={}):
        """
        Creates History entry on Vulnerabilitty is fixed by package.
        """
        print("PACKAGE FIXED")
        return cls.objects.log_action(
            package=package,
            action_type=4,
            actor_name=importer,
            supporting_data=supporting_data,
        )


# class PackageVulnerabilityChangeLog(ChangeLog):
#     package = models.ForeignKey(
#         Package,
#         on_delete=models.CASCADE,
#     )

#     vulnerability = models.ForeignKey(
#         Vulnerability,
#         on_delete=models.CASCADE,
#     )

#     fix = models.BooleanField(
#         default=False,
#     )


# class PackageVulnerabilityHistoryManager(models.Manager):
#     def get_queryset(self):
#         return super().get_queryset().select_related(None)

#     def get_for_vulnerability(self, vuln, **kwargs):
#         return self.filter(
#             vulnerability=vuln,
#             **kwargs,
#         )

#     def get_for_package(self, package, **kwargs):
#         return self.filter(
#             package=package,
#             **kwargs,
#         )

#     def log_action(self, package, vulnerability, advisory, message=""):
#         """
#         Creates a History entry for a given `obj` on Addition, Change, and Deletion.
#         We do not log addition for object that inherit the HistoryFieldsMixin since
#         the `created_by` and `created_date` are already set on its model.
#         """
#         if isinstance(message, list):
#             message = json.dumps(message)

#         return self.model.objects.get_or_create(
#             vulnerability=vulnerability,
#             package=package,
#             advisory=advisory,
#             change_message=message,
#         )


# class PackageVulnerabilityChangeLog(models.Model):
#     package = models.ForeignKey(
#         Package,
#         on_delete=models.CASCADE,
#     )

#     vulnerability = models.ForeignKey(
#         Vulnerability,
#         on_delete=models.CASCADE,
#     )

#     advisory = models.ForeignKey(
#         Advisory,
#         on_delete=models.CASCADE,
#     )

#     change_message = models.TextField(
#         blank=True,
#     )

#     action_time = models.DateTimeField(
#         default=timezone.now,
#         editable=False,
#     )

#     objects = PackageVulnerabilityHistoryManager()

#     @classmethod
#     def log_change(cls, package, vulnerability, advisory, message=""):
#         """
#         Creates History entry on Change.
#         """
#         return cls.objects.log_action(
#             vulnerability=vulnerability,
#             package=package,
#             message=message,
#             advisory=advisory,
#         )

#     class Meta:
#         abstract = True


# class FixingPackageVulnerabilityChangeLog(PackageVulnerabilityChangeLog):
#     """
#     This class is used to log changes to the FixingPackageVulnerability model.
#     """

#     pass


# class PackageAffectedByVulnerabilityChangeLog(PackageVulnerabilityChangeLog):
#     """
#     This class is used to log changes to the PackageAffectedByVulnerability model.
#     """

#     pass


# class PackageHistoryManager(models.Manager):
#     def get_queryset(self):
#         return super().get_queryset().select_related(None)

#     def get_for_object(self, vuln, **kwargs):
#         return self.filter(
#             vulnerability=vuln,
#             **kwargs,
#         )

#     def log_action(self, improver, package, advisory, importer, message=""):
#         """
#         Creates a History entry for a given `obj` on Addition, Change, and Deletion.
#         We do not log addition for object that inherit the HistoryFieldsMixin since
#         the `created_by` and `created_date` are already set on its model.
#         """
#         if isinstance(message, list):
#             message = json.dumps(message)

#         return self.model.objects.get_or_create(
#             advisory=advisory,
#             importer=importer,
#             package=package,
#             change_message=message,
#         )


# class PackageChangeLog(models.Model):

#     change_message = models.TextField(
#         blank=True,
#     )

#     package = models.ForeignKey(
#         Package,
#         on_delete=models.CASCADE,
#     )

#     importer = models.ForeignKey(
#         Importer,
#         on_delete=models.CASCADE,
#         null=True,
#     )

#     advisory = models.ForeignKey(
#         Advisory,
#         on_delete=models.CASCADE,
#         null=True,
#     )

#     action_time = models.DateTimeField(
#         default=timezone.now,
#         editable=False,
#     )

#     objects = PackageHistoryManager()

#     @classmethod
#     def log_change(cls, improver, package, message, advisory, importer):
#         """
#         Creates History entry on Change.
#         """
#         return cls.objects.log_action(
#             importer=importer,
#             package=package,
#             advisory=advisory,
#             message=message,
#         )


# class History(models.Model):
#     ADDITION = ADDITION
#     CHANGE = CHANGE
#     DELETION = DELETION

#     ACTION_FLAG_CHOICES = (
#         (ADDITION, _("Addition")),
#         (CHANGE, _("Change")),
#         (DELETION, _("Deletion")),
#     )

#     # consider removing this field
#     serialized_data = models.TextField(
#         null=True,
#         blank=True,
#         editable=False,
#         help_text=_("Serialized data of the instance just before this change."),
#     )

#     # The following fields are directly taken from django.contrib.admin.models.LogEntry
#     # Since the LogEntry is not abstract we cannot properly inherit from it.

#     action_time = models.DateTimeField(
#         _("action time"),
#         default=timezone.now,
#         editable=False,
#     )

#     improver = models.ForeignKey(
#         Improver,
#         models.CASCADE,
#         verbose_name=_("improver"),
#         null=True,
#     )

#     importer = models.ForeignKey(
#         Importer,
#         models.CASCADE,
#         verbose_name=_("importer"),
#         null=True,
#     )

#     content_type = models.ForeignKey(
#         ContentType,
#         models.SET_NULL,
#         verbose_name=_("content type"),
#         blank=True,
#         null=True,
#         # help_text="Type of object referenced by this log entry. for example, `Package`",
#     )

#     advisory = models.ForeignKey(
#         Advisory,
#         models.CASCADE,
#         verbose_name=_("advisory"),
#         null=True,
#     )

#     object_id = models.TextField(
#         _("object id"),
#         blank=True,
#         null=True,
#     )

#     object_repr = models.CharField(
#         _("object repr"),
#         max_length=200,
#     )

#     action_flag = models.PositiveSmallIntegerField(
#         _("action flag"),
#         choices=ACTION_FLAG_CHOICES,
#     )

#     # change_message is either a string or a JSON structure
#     change_message = models.TextField(
#         _("change message"),
#         blank=True,
#     )

#     objects = HistoryManager()

#     class Meta:
#         verbose_name = _("history entry")
#         verbose_name_plural = _("history entries")
#         ordering = ("-action_time",)

#     # Clone the method from Django's LogEntry model.
#     __repr__ = LogEntry.__repr__
#     __str__ = LogEntry.__str__
#     is_addition = LogEntry.is_addition
#     is_change = LogEntry.is_change
#     is_deletion = LogEntry.is_deletion
#     get_change_message = LogEntry.get_change_message
#     get_edited_object = LogEntry.get_edited_object

#     @classmethod
#     def log_addition(cls, improver, obj, advisory, importer, message=None):
#         """
#         Creates History entry on Addition with the proper `change_message`.
#         """
#         if not message:
#             message = [{"added": {}}]

#         return cls.objects.log_action(
#             improver=improver,
#             obj=obj,
#             action_flag=cls.ADDITION,
#             advisory=advisory,
#             message=message,
#             importer=importer,
#         )

#     @classmethod
#     def log_change(cls, improver, obj, message, advisory, importer, serialized_data=None):
#         """
#         Creates History entry on Change.
#         """
#         return cls.objects.log_action(
#             improver=improver,
#             importer=importer,
#             obj=obj,
#             action_flag=cls.CHANGE,
#             advisory=advisory,
#             message=message,
#             serialized_data=serialized_data,
#         )
