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
from django.db.models import Prefetch
from django.db.models import Q
from django.db.models.functions import Length
from django.db.models.functions import Trim
from django.urls import reverse
from packageurl import PackageURL
from packageurl.contrib.django.models import PackageURLMixin
from packageurl.contrib.django.models import PackageURLQuerySet
from packageurl.contrib.django.models import without_empty_values
from rest_framework.authtoken.models import Token
from univers import versions

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import build_vcid
from vulnerabilities.utils import remove_qualifiers_and_subpath

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

    def get_fixed_packages(self, package):
        """
        Return a queryset of all packages that fix a vulnerability with
        same type, namespace, name, subpath and qualifiers of the `package`
        """
        return Package.objects.filter(
            name=package.name,
            namespace=package.namespace,
            type=package.type,
            qualifiers=package.qualifiers,
            subpath=package.subpath,
            packagerelatedvulnerability__fix=True,
        ).distinct()

    def get_sibling_packages(self, package):
        """
        Return a queryset of all packages with the same type, namespace, name, subpath and qualifiers of the `package`, whether or not they fix any vulnerability
        """
        return Package.objects.filter(
            name=package.name,
            namespace=package.namespace,
            type=package.type,
            qualifiers=package.qualifiers,
            subpath=package.subpath,
            # packagerelatedvulnerability__fix=True,
        ).distinct()

    # def assign_and_compare_univers_versions(self, fixed_pkg):
    def assign_univers_version(self, fixed_pkg):
        """
        Identify which univers version applies to the two packages to be compared (self and a fixed package),
        evaluate whether the fixed_pkg version is > than the target affected package, and
        return True or False.
        """

        # TODO: Instead of return True or False based on evaluating the incoming fixed_pkg type to a univers version and then checking whether the fixed version is greater than the affected (self) version, we'll just use the incoming type to assign and return a univers version -- as command_name -- to be used in get_closest_fixed_package() below to add all greater-than versions to the later_matching_fixed_packages list -- which in turn will be fed to self.sort_by_version(later_matching_fixed_packages)

        # Many more to be added.
        match_type_to_univers_version = {
            "conan": versions.ConanVersion,
            "deb": versions.DebianVersion,
            "maven": versions.MavenVersion,
            "openssl": versions.OpensslVersion,
            "pypi": versions.PypiVersion,
        }

        command_name = ""

        matched_type_to_version = match_type_to_univers_version.get(fixed_pkg.type)
        if matched_type_to_version:
            print("\t--------------------------")
            print("*** matched_type_to_version = {}".format(matched_type_to_version))
            command_name = matched_type_to_version

        else:
            print("\t--------------------------")
            print("*** matched_type_to_version = NO MATCH")
            # Using "command_name = versions.Version", the test
            # assert versions.Version("0.9") < versions.Version("0.10")
            # fails!
            # command_name = versions.Version
            # Use this as a default fallback instead.
            command_name = versions.SemverVersion

        # if command_name(fixed_pkg.version) > command_name(self.version):
        #     return True
        # else:
        #     return False

        # Instead return command_name for recipient to use as needed for sorting or perhaps other uses
        return command_name

    def sort_by_version(self, later_matching_fixed_packages):
        # Incoming is a list of <class 'vulnerabilities.models.Package'>

        # ALERT: added this to address server error 500 but related error arose: line 908, in get_closest_fixed_package
        # HOT: How is this related to the source of the server error (500)?
        if len(later_matching_fixed_packages) == 0:
            return

        # Replace find_closest_fixed_by_package()?
        print("\nlater_matching_fixed_packages = {}".format(later_matching_fixed_packages))
        print("\nlater_matching_fixed_packages[0] = {}".format(later_matching_fixed_packages[0]))
        print(
            "\ntype(later_matching_fixed_packages[0]) = {}".format(
                type(later_matching_fixed_packages[0])
            )
        )
        # NOTE: This gives us the PURL type but instead we want the PURL itself to pass to assign_univers_version(self, fixed_pkg) and get the command_name in return, which we'll then use in the sort process.
        print(
            "\nlater_matching_fixed_packages[0].type = {}".format(
                later_matching_fixed_packages[0].type
            )
        )
        print(
            "\ntype(later_matching_fixed_packages[0].type) = {}".format(
                type(later_matching_fixed_packages[0].type)
            )
        )

        # Incoming is a list -- later_matching_fixed_packages

        # We'll use assign_univers_version() above to get the univers version as a command_name.
        # But what do we pass to it?  The [0] index of the incoming list, i.e., later_matching_fixed_packages[0]?
        command_name = self.assign_univers_version(later_matching_fixed_packages[0])

        print("\n>>> command_name = {}\n".format(command_name))

        # TODO: Maybe we don't need to convert to a PURL, a list of dictionaries etc.??
        print(
            "\n+++++++ later_matching_fixed_packages[0].version = {}".format(
                later_matching_fixed_packages[0].version
            )
        )

        # sort
        test_sort_by_version = []
        test_sort_by_version = sorted(
            # later_matching_fixed_packages, key=lambda x: versions.DebianVersion(x["version"])
            later_matching_fixed_packages,
            # key=lambda x: versions.MavenVersion(x.version),
            key=lambda x: command_name(x.version),
        )

        print("\ntest_sort_by_version = {}\n".format(test_sort_by_version))

        return test_sort_by_version

        # convert_to_dict_list = []

        # sorted_later_matching_fixed_packages = []

        # # TODO: First, convert to a list of dictionaries.
        # for pkg in later_matching_fixed_packages:
        #     # pkg is a <class 'vulnerabilities.models.Package'>
        #     print("pkg = {}".format(pkg))
        #     print("type(pkg) = {}".format(type(pkg)))

        #     # pkg_str is a string
        #     pkg_str = pkg.package_url
        #     print("pkg_str = {}".format(pkg_str))
        #     print("type(pkg_str) = {}".format(type(pkg_str)))

        #     # purl is a <class 'packageurl.PackageURL'>
        #     purl = PackageURL.from_string(pkg_str)
        #     print("purl = {}".format(purl))
        #     print("type(purl) = {}".format(type(purl)))

        #     purl_dict = purl.to_dict()
        #     print("purl_dict = {}".format(purl_dict))
        #     print("type(purl_dict) = {}".format(type(purl_dict)))

        #     convert_to_dict_list.append(purl.to_dict())
        #     print("HELLO\n")

        # print("\nconvert_to_dict_list = {}\n".format(convert_to_dict_list))

        # return convert_to_dict_list
        # ==========================================================
        # sorted_later_matching_fixed_packages = sorted(
        #     later_matching_fixed_packages, key=lambda x: versions.MavenVersion(x["version"])
        # )
        # print(
        #     "\nsorted_later_matching_fixed_packages = {}\n".format(
        #         sorted_later_matching_fixed_packages
        #     )
        # )
        # print("\n".join(map(str, sorted_later_matching_fixed_packages)))

        # return what?

    # ==========================================================
    # ==========================================================

    # def find_closest_fixed_by_package(self, later_matching_fixed_packages):
    #     # Maybe use sort_by_version() above instead?
    #     # take the incoming list later_matching_fixed_packages, convert to list of dictionaries, sort by version using univers.version.[version class], choose the top i.e., index [0] and convert back to PURL and return that PURL.
    #     print("\nlater_matching_fixed_packages = {}\n".format(later_matching_fixed_packages))

    #     closest_fixed_by_package = "TBD"

    #     return closest_fixed_by_package

    @property
    # def get_fixing_packages(self):
    def get_closest_fixed_package(self):
        """
        This function identifies the closest fixed package version that is greater than the affected package version and
        is the same type, namespace, name, qualifiers and subpath as the affected package.
        """

        print("\nself = {}\n".format(self))

        # This returns all fixed packages that match the target package (type etc.), regardless of fixed vuln.
        # fixed_packages = self.get_fixed_packages(package=self)
        # This is clearer.
        matching_fixed_packages = self.get_fixed_packages(package=self)

        # This returns a list of the vulnerabilities that affect this package (i.e., self).
        qs = self.vulnerabilities.filter(packagerelatedvulnerability__fix=False)

        # This takes the list of vulns affecting the current package, retrieves a list of the fixed packages for each vuln, and assigns the result to a custom attribute, `filtered_fixed_packages` (renamed 'matching_fixed_packages').
        # We use this in a for loop below like this -- qs[vuln_count].filtered_fixed_packages (renamed 'matching_fixed_packages') -- where `vuln_count` is used to iterate through the list of vulns that affect the current package (i.e., self).
        qs = qs.prefetch_related(
            Prefetch(
                "packages",
                # queryset=fixed_packages,
                queryset=matching_fixed_packages,
                # to_attr="filtered_fixed_packages",
                to_attr="matching_fixed_packages",
            )
        )

        # Ex: qs[0].filtered_fixed_packages gives us the fixed package(s) for the 1st vuln for this affected package (i.e., self).
        print("qs = {}\n".format(qs))

        # ************************************************************************

        later_matching_fixed_packages = []

        vuln_count = 0
        for vuln in qs:
            print("vuln = {}\n".format(vuln))
            # print(
            #     "\tqs[vuln_count].filtered_fixed_packages = {}".format(
            #         qs[vuln_count].filtered_fixed_packages
            #     )
            # )
            print(
                "\tqs[vuln_count].matching_fixed_packages = {}".format(
                    qs[vuln_count].matching_fixed_packages
                )
            )
            print("")

            # Check the Prefetch qs.
            # TODO: Do we want to check whether the fixed version has any vulnerabilities of its own?
            # for fixed_pkg in qs[vuln_count].filtered_fixed_packages:
            for fixed_pkg in qs[vuln_count].matching_fixed_packages:
                print("\tfixed_pkg = {}".format(fixed_pkg))
                print("\tfixed_pkg.type = {}".format(fixed_pkg.type))
                print("\tfixed_pkg.version = {}".format(fixed_pkg.version))
                print("\t--------------------------")
                print("\tself.type = {}".format(self.type))
                print("\tself.version = {}".format(self.version))

                # Assign univers version and compare: False = fixed_pkg.version < self.version (affected version).

                # 2023-08-02 Wednesday 16:01:35.  atm immediate_fix is True or False.  If instead assign_and_compare_univers_versions() returns the univers version, we could get that here and then test with this or similar right here -- enabling use of the univers version function in other places as well, like a sort_by_version function!
                # if command_name(fixed_pkg.version) > command_name(self.version):
                #     return True
                # else:
                #     return False
                # =====================================================
                # Replace this with chunk below
                # immediate_fix = self.assign_and_compare_univers_versions(fixed_pkg)
                # print("\t--------------------------")
                # print("\timmediate_fix = {}\n".format(immediate_fix))

                # if fixed_pkg in fixed_packages and immediate_fix:
                #     later_matching_fixed_packages.append(fixed_pkg)
                # =====================================================
                # command_name = self.assign_and_compare_univers_versions(fixed_pkg)
                # renamed
                # TODO: Move this up before the for loop -- both for loops if possible -- to reduce calls!
                command_name = self.assign_univers_version(fixed_pkg)
                print("\nJust requested command_name >>> {}\n".format(command_name))
                # if fixed_pkg in fixed_packages and command_name(fixed_pkg.version) > command_name(
                #     self.version
                # ):
                if fixed_pkg in matching_fixed_packages and command_name(
                    fixed_pkg.version
                ) > command_name(self.version):
                    later_matching_fixed_packages.append(fixed_pkg)

            vuln_count += 1

        # find_closest_fixed_by_package -- from the list later_matching_fixed_packages
        # closest_fixed_by_package = self.find_closest_fixed_by_package(later_matching_fixed_packages)

        # TODO: or instead use this.  This will be a list sorted by univers version class, and here all we need is to grab the [0] index from that list for the closest fixed by package!  So we'd return a single closest_fixed_package.
        # ALERT: The sort query needs to be done separately for each vulnerability because the list of fixed by packages is likely to be different.  As is, we return a single sorted list of all fixed by packages for the affected package and then pass just the [0] package -- not what we want to do!
        sort_fixed_by_packages_by_version = self.sort_by_version(later_matching_fixed_packages)
        print(
            "\nsort_fixed_by_packages_by_version = {}\n".format(sort_fixed_by_packages_by_version)
        )
        # ALERT: 2023-08-05 Saturday 23:22:08.  Address server error 500?
        # ALERT: 2023-08-05 Saturday 23:24:50.  This actusally fixed the server error (500) and I can now even see the Packafe details page for pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0-rc1 !!!
        # HOT: I need to trace back the root cause of the server error (500).  I suspect it's something like a record with no fixed by packages or something else that is an empty list but which i try to measure, e.g., for a print statement, or possibly for a real if condition..
        if sort_fixed_by_packages_by_version is None:
            return

        closest_fixed_package = sort_fixed_by_packages_by_version[0]

        # print("\n!!! later_matching_fixed_packages = {}\n".format(later_matching_fixed_packages))
        # print(
        #     "\n!!! sort_fixed_by_packages_by_version = {}\n".format(
        #         sort_fixed_by_packages_by_version
        #     )
        # )
        # print("\n!!! closest_fixed_package = {}\n".format(closest_fixed_package))

        # rebuilt_purl_from_dict = PackageURL(
        #     closest_fixed_package["type"],
        #     closest_fixed_package["namespace"],
        #     closest_fixed_package["name"],
        #     closest_fixed_package["version"],
        #     closest_fixed_package["qualifiers"],
        #     closest_fixed_package["subpath"],
        # )
        # print("\n!!! rebuilt_purl_from_dict = {}\n".format(rebuilt_purl_from_dict))

        # return later_matching_fixed_packages
        return sort_fixed_by_packages_by_version
        # return [closest_fixed_package]

        # return [rebuilt_purl_from_dict]

    @property
    def fixed_package_details(self):
        """
        This is a test that might develop into a model-based equivalent of the loops etc. I was doing/trying to do in the Jinja2 template.  I'm going to add this as a context so we can see it in the template.
        """
        # return "Hello"

        # vcio_dict = {
        #     [
        #         {"VCID-2nyb-8rwu-aaag": "PURL01"},
        #         {"VCID-gqhw-ngh8-aaap": "PURL02"},
        #         {"some-other-id": "PURL03"},
        #     ]
        # }

        print("\n==> This is from the test_property_01() property.\n")

        print("\nself = {}\n".format(self))

        # This returns all fixed packages that match the target package (type etc.), regardless of fixed vuln.
        # fixed_packages = self.get_fixed_packages(package=self)
        # This is clearer.
        matching_fixed_packages = self.get_fixed_packages(package=self)

        # This returns a list of the vulnerabilities that affect this package (i.e., self).
        qs = self.vulnerabilities.filter(packagerelatedvulnerability__fix=False)

        # TODO: Can we get all sibling packages so that we can then determine which have 0 vulnerabilities and of these the closest and maybe the most recent as well?

        all_sibling_packages = self.get_sibling_packages(package=self)
        print("\nall_sibling_packages = {}\n".format(all_sibling_packages))
        print("\nlen(all_sibling_packages) = {}\n".format(len(all_sibling_packages)))

        non_vuln_sibs = []
        for sib in all_sibling_packages:
            if sib.is_vulnerable is False:
                non_vuln_sibs.append(sib)
        print("\nnon_vuln_sibs = {}\n".format(non_vuln_sibs))
        print("\nlen(non_vuln_sibs) = {}\n".format(len(non_vuln_sibs)))

        # Add just the greater-than versions to a new list
        command_name = self.assign_univers_version(self)
        print(
            "\nOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO command_name = {}\n".format(
                command_name
            )
        )
        later_non_vuln_sibs = []
        for non_vuln_sib in non_vuln_sibs:
            if command_name(non_vuln_sib.version) > command_name(self.version):
                later_non_vuln_sibs.append(non_vuln_sib)

        print("\nlater_non_vuln_sibs = {}\n".format(later_non_vuln_sibs))
        print("\nlen(later_non_vuln_sibs) = {}\n".format(len(later_non_vuln_sibs)))

        # This takes the list of vulns affecting the current package, retrieves a list of the fixed packages for each vuln, and assigns the result to a custom attribute, `filtered_fixed_packages` (renamed 'matching_fixed_packages').
        # We use this in a for loop below like this -- qs[vuln_count].filtered_fixed_packages (renamed 'matching_fixed_packages') -- where `vuln_count` is used to iterate through the list of vulns that affect the current package (i.e., self).
        qs = qs.prefetch_related(
            Prefetch(
                "packages",
                # queryset=fixed_packages,
                queryset=matching_fixed_packages,
                # to_attr="filtered_fixed_packages",
                to_attr="matching_fixed_packages",
            )
        )

        # Ex: qs[0].filtered_fixed_packages gives us the fixed package(s) for the 1st vuln for this affected package (i.e., self).
        print("\nzzz qs = {}\n".format(qs))

        purl_dict = {}

        purl_dict["purl"] = self.purl

        purl_dict.update({"vulnerabilities": []})

        # purl_dict["vulnerabilities"].append({"fruit": "orange"})

        for vuln in qs:
            print("\nzzz vuln = {}\n".format(vuln))
            print("\nzzz type(vuln) = {}\n".format(type(vuln)))

            later_matching_fixed_packages = []
            # purl_dict[vuln.vulnerability_id] = "aaa"
            # purl_dict.update({"vulnerability": vuln.vulnerability_id})

            purl_dict["vulnerabilities"].append({"vulnerability": vuln.vulnerability_id})

            # TODO:2023-08-05 Saturday 13:12:28.  This returns a list of matching fixed packages for this specific vuln!
            vuln_matching_fixed_packages = vuln.matching_fixed_packages
            print("\nzzz self.purl = {}\n".format(self.purl))
            print("\nzzz vuln = {}\n".format(vuln))
            print("\nzzz vuln_matching_fixed_packages = {}\n".format(vuln_matching_fixed_packages))

            # TODO: So we need to sort this list by version using the correct univers version and then return the [0] index in that sorted list
            # QUESTION: Do we still need to remove lesser-than fixed packages or did we already do that?

            # =============================================================
            # command_name = self.assign_univers_version(fixed_pkg)
            command_name = self.assign_univers_version(self)
            print("\nzzz command_name = {}\n".format(command_name))

            # ALERT: What if there are no fixed by packages?  The following thows an error because the list 'vuln_matching_fixed_packages' is empty!
            # [I fixed this, right? ;-]

            closest_fixed_package = ""

            if len(vuln_matching_fixed_packages) > 0:

                for fixed_pkg in vuln_matching_fixed_packages:
                    if fixed_pkg in matching_fixed_packages and command_name(
                        fixed_pkg.version
                    ) > command_name(self.version):
                        later_matching_fixed_packages.append(fixed_pkg)

                # print("\nJust requested command_name >>> {}\n".format(command_name))
                # # if fixed_pkg in fixed_packages and command_name(fixed_pkg.version) > command_name(
                # #     self.version
                # # ):
                # if fixed_pkg in matching_fixed_packages and command_name(
                #     fixed_pkg.version
                # ) > command_name(self.version):
                #     later_matching_fixed_packages.append(fixed_pkg)
                # =============================================================
                # later_matching_fixed_packages = vuln.matching_fixed_packages

                print(
                    "\nzzz later_matching_fixed_packages = {}\n".format(
                        later_matching_fixed_packages
                    )
                )

                sort_fixed_by_packages_by_version = self.sort_by_version(
                    later_matching_fixed_packages
                )
                print(
                    "\nzzz sort_fixed_by_packages_by_version = {}\n".format(
                        sort_fixed_by_packages_by_version
                    )
                )
                closest_fixed_package = sort_fixed_by_packages_by_version[0]
                # closest_fixed_package = sort_fixed_by_packages_by_version[0].purl
                # 2023-08-06 Sunday 11:15:03.  This returns a queryset of vulns affecting this package.
                # HOT: How do we get the closest fixed by package vuln count and list of vulns?  I keep getting errors.  ;-)
                closest_fixed_package_vulns = closest_fixed_package.affected_by
                # closest_fixed_package_vulns_list = list(closest_fixed_package_vulns)
                # ALERT: 2023-08-06 Sunday 14:25:49.  This did the trick!

                # closest_fixed_package_vulns_list = [
                #     i.vulnerability_id for i in closest_fixed_package_vulns
                # ]

                # 2023-08-06 Sunday 16:53:27.  Try a named tuple to pass the vuln's vulnerability+id and get_absolute_url.
                # FixedPackageVuln = namedtuple("FixedPackageVuln", "vuln_id, vuln_get_absolute_url")
                # closest_fixed_package_vulns_list = [
                #     FixedPackageVuln(
                #         vuln_id=fixed_pkg_vuln.vulnerability_id,
                #         vuln_get_absolute_url=fixed_pkg_vuln.get_absolute_url(),
                #     )
                #     for fixed_pkg_vuln in closest_fixed_package_vulns
                # ]
                # ALERT: Replace the namedtuple with a dict -- this way it can be added to the purl_dict as a nested dict rather than a list of 2 values.
                closest_fixed_package_vulns_dict = [
                    {
                        "vuln_id": fixed_pkg_vuln.vulnerability_id,
                        "vuln_get_absolute_url": fixed_pkg_vuln.get_absolute_url(),
                    }
                    for fixed_pkg_vuln in closest_fixed_package_vulns
                ]

                # ===
                # closest_fixed_package_vulns_list = closest_fixed_package_vulns.objects.values_list()

                # closest_fixed_package_vulns_list = []
                # for closest_vuln in closest_fixed_package_vulns:
                #     closest_fixed_package_vulns_list.append(closest_vuln)
                #     print(
                #         "\t\nQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ vuln = {}\n".format(
                #             closest_vuln
                #         )
                #     )
                #     print("\t\ntype(closest_vuln) = {}".format(type(closest_vuln)))

                # # closest_fixed_package_vuln_count = len(closest_fixed_package.affected_by)
                # print(
                #     "\t\n^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ type(closest_fixed_package_vulns) = {}\n".format(
                #         type(closest_fixed_package_vulns)
                #     )
                # )

            else:
                closest_fixed_package = "There are no reported fixed packages."
                # Is None the value we want?  We do not want to display anything but the count = 0.
                # closest_fixed_package_vulns = None
                # closest_fixed_package_vuln_count = 0

                # closest_fixed_package_vulns_list = []

            print("\nzzz closest_fixed_package = {}".format(closest_fixed_package))
            print("zzz type(closest_fixed_package) = {}\n".format(type(closest_fixed_package)))

            # TODO: How do we add 'closest_fixed_by_purl', 'closest_fixed_by_vulns' and 'non_vulnerable_fix'?

            #     # for vuln in purl_dict["vulnerabilities"]:
            #     #     # vuln["closest_fixed_by_purl"] = "?????"
            #     #     vuln["closest_fixed_by_purl"] = closest_fixed_package
            #     #     vuln["closest_fixed_by_url"] = "?????"
            #     #     vuln["closest_fixed_by_vulnerabilities"] = "?????"
            #     #     vuln["non_vulnerable_fix"] = "?????"
            #     #     vuln["non_vulnerable_fix_url"] = "?????"

            for dict_vuln in purl_dict["vulnerabilities"]:
                print("\n===================================> vuln = {}\n".format(vuln))
                print("\n===================================> type(vuln) = {}\n".format(type(vuln)))
                print("\n===================================> vuln.vcid = {}\n".format(vuln.vcid))
                print(
                    "\n===================================> dict_vuln['vulnerability'] = {}\n".format(
                        dict_vuln["vulnerability"]
                    )
                )
                # TODO: Up above we defined 'non_vuln_sibs' but we still need to remove those with less than version
                # ALERT: remove less than versions from 'non_vuln_sibs'
                # 2023-08-05 Saturday 20:30:47.  Hopefully just wrote the code for that up above, with the new list 'later_non_vuln_sibs'.

                closest_non_vulnerable_fix = ""
                # if len(non_vuln_sibs) > 0:
                #     closest_non_vulnerable_fix = self.sort_by_version(non_vuln_sibs)[0]
                if len(later_non_vuln_sibs) > 0:
                    closest_non_vulnerable_fix = self.sort_by_version(later_non_vuln_sibs)[0]
                # else:
                #     # closest_non_vulnerable_fix = (
                #     #     "There are no reported non-vulnerable fixed packages."
                #     # )
                #     closest_non_vulnerable_fix = None

                most_recent_non_vulnerable_fix = ""
                if len(later_non_vuln_sibs) > 0:
                    most_recent_non_vulnerable_fix = self.sort_by_version(later_non_vuln_sibs)[-1]
                else:
                    # most_recent_non_vulnerable_fix = (
                    #     "There are no reported non-vulnerable fixed packages."
                    # )
                    most_recent_non_vulnerable_fix = None

                # if dict_vuln["vulnerability"] == vuln.vulnerability_id:
                if dict_vuln["vulnerability"] == str(vuln):
                    # if dict_vuln["vulnerability"] == vuln.vcid:
                    # dict_vuln["closest_fixed_by_purl"] = "?????"
                    dict_vuln["closest_fixed_by_purl"] = str(closest_fixed_package)
                    dict_vuln["closest_fixed_by_url"] = closest_fixed_package.get_absolute_url()
                    # dict_vuln["closest_fixed_by_vulnerabilities"] = closest_fixed_package_vuln_count
                    # dict_vuln["closest_fixed_by_vulnerabilities"] = closest_fixed_package_vulns
                    # dict_vuln["closest_fixed_by_vulnerabilities"] = ["A", "B"]

                    # dict_vuln["closest_fixed_by_vulnerabilities"] = closest_fixed_package_vulns_list
                    # ALERT: Replace the above list created with a namedtuple with the following dictionary:
                    dict_vuln["closest_fixed_by_vulnerabilities"] = closest_fixed_package_vulns_dict
                    # ALERT: Moved these up 1 level in the dict.
                    # dict_vuln["closest_non_vulnerable_fix"] = str(closest_non_vulnerable_fix)
                    # dict_vuln[
                    #     "closest_non_vulnerable_fix_url"
                    # ] = closest_non_vulnerable_fix.get_absolute_url()
                    # dict_vuln["most_recent_non_vulnerable_fix"] = str(
                    #     most_recent_non_vulnerable_fix
                    # )
                    # dict_vuln[
                    #     "most_recent_non_vulnerable_fix_url"
                    # ] = most_recent_non_vulnerable_fix.get_absolute_url()

                    # QUESTION: Can we add the non-vuln data as higher-level key-value pairs rather than children of "vulnerabilities"?

                    # purl_dict.update({"fruits": []})
                    # purl_dict["fruits"].append({"fruit": "apple"})
                    # purl_dict["fruits"].append({"fruit": "banana"})

                    # purl_dict.update(
                    #     {"closest_non_vulnerable_fix": str(closest_non_vulnerable_fix)}
                    # )
                    # purl_dict.update(
                    #     {
                    #         "closest_non_vulnerable_fix_url": closest_non_vulnerable_fix.get_absolute_url()
                    #     }
                    # )
                    # purl_dict.update(
                    #     {"most_recent_non_vulnerable_fix": str(most_recent_non_vulnerable_fix)}
                    # )
                    # purl_dict.update(
                    #     {
                    #         "most_recent_non_vulnerable_fix_url": most_recent_non_vulnerable_fix.get_absolute_url()
                    #     }
                    # )

                    purl_dict["closest_non_vulnerable_fix"] = str(closest_non_vulnerable_fix)
                    purl_dict[
                        "closest_non_vulnerable_fix_url"
                    ] = closest_non_vulnerable_fix.get_absolute_url()
                    purl_dict["most_recent_non_vulnerable_fix"] = str(
                        most_recent_non_vulnerable_fix
                    )
                    purl_dict[
                        "most_recent_non_vulnerable_fix_url"
                    ] = most_recent_non_vulnerable_fix.get_absolute_url()

        print("\npurl_dict = {}\n".format(purl_dict))

        print(json.dumps(purl_dict, indent=4, sort_keys=False))

        # # Print to text file
        pretty_purl_dict = json.dumps(purl_dict, indent=4, sort_keys=False)
        # logger = logging.getLogger(__name__)
        # logger.setLevel(logging.INFO)
        # # logger.addHandler(logging.FileHandler("2023-08-07-pretty_purl_dict.txt"))
        # # will this overwrite prior writes?  weird output
        # logger.addHandler(logging.FileHandler("2023-08-07-pretty_purl_dict.txt", mode="w"))
        # logger.info(pretty_purl_dict)

        with open("/home/jmh/pretty_purl_dict.txt", "w") as f:
            f.write(pretty_purl_dict)

        alternate_dict_01 = {
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1",
            "vulnerabilities": [
                {
                    "vulnerability": "VCID-2nyb-8rwu-aaag",
                    "closest_fixed_by_purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2",
                    # "get_absolute_url": reverse("package_details", args=[self.purl]),
                    "closest_fixed_by_url": reverse(
                        "package_details",
                        args=["pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2"],
                    ),
                    "closest_fixed_by_vulns": 2,
                    "non_vulnerable_fix": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0-rc1",
                    "non_vulnerable_fix_url": reverse(
                        "package_details",
                        args=["pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0-rc1"],
                    ),
                },
                {
                    "vulnerability": "VCID-gqhw-ngh8-aaap",
                    "closest_fixed_by_purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4",
                    # "get_absolute_url": reverse("package_details", args=[self.purl]),
                    "closest_fixed_by_url": reverse(
                        "package_details",
                        args=["pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.4"],
                    ),
                    "closest_fixed_by_vulns": 1,
                    "non_vulnerable_fix": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0-rc1",
                    "non_vulnerable_fix_url": reverse(
                        "package_details",
                        args=["pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0-rc1"],
                    ),
                },
                {
                    "vulnerability": "VCID-t7e4-g3fr-aaan",
                    "closest_fixed_by_purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0-rc1",
                    # "get_absolute_url": reverse("package_details", args=[self.purl]),
                    "closest_fixed_by_url": reverse(
                        "package_details",
                        args=["pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0-rc1"],
                    ),
                    "closest_fixed_by_vulns": 0,
                    "non_vulnerable_fix": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0-rc1",
                    "non_vulnerable_fix_url": reverse(
                        "package_details",
                        args=["pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.14.0-rc1"],
                    ),
                },
            ],
        }

        # return vcio_dict

        # return alternate_dict_01

        return purl_dict


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
    objects = AdvisoryQuerySet.as_manager()

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

    def to_advisory_data(self) -> AdvisoryData:
        return AdvisoryData(
            aliases=self.aliases,
            summary=self.summary,
            affected_packages=[AffectedPackage.from_dict(pkg) for pkg in self.affected_packages],
            references=[Reference.from_dict(ref) for ref in self.references],
            date_published=self.date_published,
            weaknesses=self.weaknesses,
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
