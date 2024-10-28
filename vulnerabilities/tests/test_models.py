#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import urllib.parse
from datetime import datetime
from unittest import TestCase
from unittest import mock

import pytest
from django.db import transaction
from django.db.models.query import QuerySet
from django.db.utils import IntegrityError
from freezegun import freeze_time
from packageurl import PackageURL
from univers import versions
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import AlpineLinuxVersionRange

from vulnerabilities import models
from vulnerabilities.models import Alias
from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityQuerySet


class TestVulnerabilityModel(TestCase):
    @pytest.mark.django_db
    def test_vulnerability_save_with_vulnerability_id(self):
        models.Vulnerability(vulnerability_id="CVE-2020-7965").save()
        assert models.Vulnerability.objects.filter(vulnerability_id="CVE-2020-7965").count() == 1

    @pytest.mark.django_db
    def test_cwe_not_present_in_weaknesses_db(self):
        w1 = models.Weakness.objects.create(cwe_id=189)
        assert w1.weakness is None
        assert w1.name is ""
        assert w1.description is ""


# FIXME: The fixture code is duplicated. setUpClass is not working with the pytest mark.
@pytest.mark.django_db
class TestPackageRelatedVulnerablity(TestCase):
    def test_package_to_vulnerability(self):
        p1 = models.Package.objects.create(type="deb", name="git", version="2.30.1")
        p2 = models.Package.objects.create(type="deb", name="git", version="2.31.1")
        v1 = models.Vulnerability.objects.create(vulnerability_id="CVE-123-2002")

        prv1 = models.AffectedByPackageRelatedVulnerability.objects.create(
            package=p1, vulnerability=v1
        )
        prv2 = models.FixingPackageRelatedVulnerability.objects.create(package=p2, vulnerability=v1)

        assert p1.fixing_vulnerabilities.count() == 0

        assert p2.fixing_vulnerabilities.count() == 1
        assert p2.fixing_vulnerabilities[0] == v1

    def test_vulnerability_package(self):
        p1 = models.Package.objects.create(type="deb", name="git", version="2.30.1")
        p2 = models.Package.objects.create(type="deb", name="git", version="2.31.1")
        v1 = models.Vulnerability.objects.create(vulnerability_id="CVE-123-2002")

        prv1 = models.AffectedByPackageRelatedVulnerability.objects.create(
            package=p1, vulnerability=v1
        )
        prv2 = models.FixingPackageRelatedVulnerability.objects.create(package=p2, vulnerability=v1)

        assert v1.vulnerable_packages.count() == 1
        assert v1.fixed_by_packages.count() == 1

        assert v1.vulnerable_packages[0] == p1
        assert v1.fixed_by_packages[0] == p2


@pytest.mark.django_db
class TestPackageModel(TestCase):
    def setUp(self):
        """
        This uses a package/vuln/fix group we know from the DB/UI testing: pkg:pypi/redis@4.1.1.
        It has 2 non-vuln versions, both the same: 5.0.0b1.  The first of its two vulns is
        VCID-g2fu-45jw-aaan (aliases: CVE-2023-28858 and GHSA-24wv-mv5m-xv4h), fixed by
        4.3.6 w/1 vuln of its own.  The second is VCID-rqe1-dkmg-aaad (aliases: CVE-2023-28859
        and GHSA-8fww-64cx-x8p5), fixed by 5.0.0b1 w/ 0 vulns of its own.
        """

        # pkg
        self.package_pypi_redis_4_1_1 = models.Package.objects.create(
            type="pypi",
            namespace="",
            name="redis",
            version="4.1.1",
            qualifiers={},
            subpath="",
        )

        # vuln #1 for affected pkg
        self.vuln_VCID_g2fu_45jw_aaan = models.Vulnerability.objects.create(
            summary="This is VCID-g2fu-45jw-aaan",
            vulnerability_id="VCID-g2fu-45jw-aaan",
        )

        # relationship
        models.AffectedByPackageRelatedVulnerability.objects.create(
            package=self.package_pypi_redis_4_1_1,
            vulnerability=self.vuln_VCID_g2fu_45jw_aaan,
        )

        # aliases
        Alias.objects.create(alias="CVE-2023-28858", vulnerability=self.vuln_VCID_g2fu_45jw_aaan)
        Alias.objects.create(
            alias="GHSA-24wv-mv5m-xv4h", vulnerability=self.vuln_VCID_g2fu_45jw_aaan
        )

        # fixed pkg for vuln #1 for affected pkg
        self.package_pypi_redis_4_3_6 = models.Package.objects.create(
            type="pypi",
            namespace="",
            name="redis",
            version="4.3.6",
            qualifiers={},
            subpath="",
        )

        # relationship
        models.FixingPackageRelatedVulnerability.objects.create(
            package=self.package_pypi_redis_4_3_6,
            vulnerability=self.vuln_VCID_g2fu_45jw_aaan,
        )

        # vuln for fixed pkg -- and also vuln # 2 for affected pkg
        self.vuln_VCID_rqe1_dkmg_aaad = models.Vulnerability.objects.create(
            summary="This is VCID-rqe1-dkmg-aaad",
            vulnerability_id="VCID-rqe1-dkmg-aaad",
        )

        # relationship
        models.AffectedByPackageRelatedVulnerability.objects.create(
            package=self.package_pypi_redis_4_3_6,
            vulnerability=self.vuln_VCID_rqe1_dkmg_aaad,
        )

        # aliases
        Alias.objects.create(alias="CVE-2023-28859", vulnerability=self.vuln_VCID_rqe1_dkmg_aaad)
        Alias.objects.create(
            alias="GHSA-8fww-64cx-x8p5", vulnerability=self.vuln_VCID_rqe1_dkmg_aaad
        )

        # vuln # 2 for affected pkg -- already defined above bc also vuln for fixed pkg above!

        # relationship
        models.AffectedByPackageRelatedVulnerability.objects.create(
            package=self.package_pypi_redis_4_1_1,
            vulnerability=self.vuln_VCID_rqe1_dkmg_aaad,
        )

        # aliases -- already defined above

        # fixed pkg -- 0 vulns of its own
        self.package_pypi_redis_5_0_0b1 = models.Package.objects.create(
            type="pypi",
            namespace="",
            name="redis",
            version="5.0.0b1",
            qualifiers={},
            subpath="",
        )

        # relationship
        models.FixingPackageRelatedVulnerability.objects.create(
            package=self.package_pypi_redis_5_0_0b1,
            vulnerability=self.vuln_VCID_rqe1_dkmg_aaad,
        )

        # This vulnerability does not affect any redis packages in this set of tests but does affect a made-up package, self.package_pypi_bogus_1_2_3.
        self.vuln_VCID_abcd_efgh_1234 = models.Vulnerability.objects.create(
            summary="This is VCID-abcd-efgh-1234",
            vulnerability_id="VCID-abcd-efgh-1234",
        )

        # pkg
        self.package_pypi_bogus_1_2_3 = models.Package.objects.create(
            type="pypi",
            namespace="",
            name="bogus",
            version="1.2.3",
            qualifiers={},
            subpath="",
        )

        # relationship
        models.AffectedByPackageRelatedVulnerability.objects.create(
            package=self.package_pypi_bogus_1_2_3,
            vulnerability=self.vuln_VCID_abcd_efgh_1234,
        )

        # This vulnerability does not affect any packages in this set of tests included to test .all().
        self.vuln_VCID_wxyz_0000_0000 = models.Vulnerability.objects.create(
            summary="This is VCID-wxyz-0000-0000",
            vulnerability_id="VCID-wxyz-0000-0000",
        )

    def test_fixed_package_details(self):
        searched_for_package = self.package_pypi_redis_4_1_1

        assert searched_for_package.package_url == "pkg:pypi/redis@4.1.1"
        assert searched_for_package.plain_package_url == "pkg:pypi/redis@4.1.1"
        assert searched_for_package.get_absolute_url() == "/packages/pkg:pypi/redis@4.1.1"
        assert searched_for_package.purl == "pkg:pypi/redis@4.1.1"

        assert len(searched_for_package.affected_by) == 2

        assert self.vuln_VCID_g2fu_45jw_aaan in searched_for_package.affected_by
        assert self.package_pypi_redis_4_3_6 in self.vuln_VCID_g2fu_45jw_aaan.fixed_by_packages

        assert self.vuln_VCID_rqe1_dkmg_aaad in searched_for_package.affected_by
        assert self.package_pypi_redis_5_0_0b1 in self.vuln_VCID_rqe1_dkmg_aaad.fixed_by_packages

        searched_for_package_details = searched_for_package.fixed_package_details

        package_details = {
            "purl": PackageURL(
                type="pypi",
                name="redis",
                version="4.1.1",
            ),
            "next_non_vulnerable": PackageURL(
                type="pypi",
                name="redis",
                version="5.0.0b1",
            ),
            "latest_non_vulnerable": PackageURL(
                type="pypi",
                namespace=None,
                name="redis",
                version="5.0.0b1",
                qualifiers={},
                subpath=None,
            ),
            "vulnerabilities": [
                {
                    "vulnerability": self.vuln_VCID_g2fu_45jw_aaan,
                    "fixed_by_package_details": [
                        {
                            "fixed_by_purl": PackageURL(
                                type="pypi",
                                namespace=None,
                                name="redis",
                                version="4.3.6",
                                qualifiers={},
                                subpath=None,
                            ),
                            "fixed_by_purl_vulnerabilities": [self.vuln_VCID_rqe1_dkmg_aaad],
                        }
                    ],
                    "fixed_by_purl": [],
                    "fixed_by_purl_vulnerabilities": [],
                },
                {
                    "vulnerability": self.vuln_VCID_rqe1_dkmg_aaad,
                    "fixed_by_package_details": [
                        {
                            "fixed_by_purl": PackageURL(
                                type="pypi",
                                namespace=None,
                                name="redis",
                                version="5.0.0b1",
                                qualifiers={},
                                subpath=None,
                            ),
                            "fixed_by_purl_vulnerabilities": [],
                        }
                    ],
                    "fixed_by_purl": [],
                    "fixed_by_purl_vulnerabilities": [],
                },
            ],
        }

        assert searched_for_package_details == package_details

        assert searched_for_package_details.get("latest_non_vulnerable") == PackageURL(
            type="pypi",
            namespace=None,
            name="redis",
            version="5.0.0b1",
            qualifiers={},
            subpath=None,
        )

        searched_for_package_fixing = searched_for_package.fixing
        assert type(searched_for_package_fixing) == models.VulnerabilityQuerySet
        assert searched_for_package_fixing.count() == 0
        assert len(searched_for_package_fixing) == 0
        assert list(searched_for_package_fixing) == []

    def test_get_vulnerable_packages(self):
        vuln_packages = Package.objects.vulnerable()
        assert vuln_packages.count() == 4
        assert vuln_packages.distinct().count() == 3

        first_vulnerable_package = vuln_packages.distinct()[0]
        assert first_vulnerable_package.purl == "pkg:pypi/bogus@1.2.3"

        second_vulnerable_package = vuln_packages.distinct()[1]
        assert second_vulnerable_package.purl == "pkg:pypi/redis@4.1.1"

        second_vulnerable_package_matching_fixed_packages = (
            Package.objects.get_fixed_by_package_versions(second_vulnerable_package, fix=True)
        )
        first_fixed_by_package = second_vulnerable_package_matching_fixed_packages[0]

        assert len(second_vulnerable_package_matching_fixed_packages) == 2
        assert first_fixed_by_package.purl == "pkg:pypi/redis@4.3.6"

    def test_string_to_package(self):
        purl_string = "pkg:maven/org.apache.tomcat/tomcat@10.0.0-M4"
        purl = PackageURL.from_string(purl_string)
        purl_to_dict = purl.to_dict()

        # For namespace, version, qualifiers and subpath, we need to add the or * to avoid an
        # IntegrityError, e.g., django.db.utils.IntegrityError: null value in column "subpath" violates
        # not-null constraint
        vulnerablecode_package = models.Package.objects.create(
            type=purl_to_dict.get("type"),
            namespace=purl_to_dict.get("namespace") or "",
            name=purl_to_dict.get("name"),
            version=purl_to_dict.get("version") or "",
            qualifiers=purl_to_dict.get("qualifiers") or {},
            subpath=purl_to_dict.get("subpath") or "",
        )

        assert type(vulnerablecode_package) == models.Package
        assert vulnerablecode_package.purl == "pkg:maven/org.apache.tomcat/tomcat@10.0.0-M4"
        assert vulnerablecode_package.package_url == "pkg:maven/org.apache.tomcat/tomcat@10.0.0-M4"
        assert (
            vulnerablecode_package.plain_package_url
            == "pkg:maven/org.apache.tomcat/tomcat@10.0.0-M4"
        )
        assert (
            vulnerablecode_package.get_absolute_url()
            == "/packages/pkg:maven/org.apache.tomcat/tomcat@10.0.0-M4"
        )

    def test_univers_version_comparisons(self):
        assert versions.PypiVersion("1.2.3") < versions.PypiVersion("1.2.4")
        assert versions.PypiVersion("0.9") < versions.PypiVersion("0.10")

        deb01 = models.Package.objects.create(type="deb", name="git", version="2.30.1")
        deb02 = models.Package.objects.create(type="deb", name="git", version="2.31.1")
        assert versions.DebianVersion(deb01.version) < versions.DebianVersion(deb02.version)

        # pkg:deb/debian/jackson-databind@2.12.1-1%2Bdeb11u1 is a real PURL in the DB
        # But we need to replace/delete the "%".  Test the error:
        with pytest.raises(versions.InvalidVersion):
            assert versions.DebianVersion("2.12.1-1%2Bdeb11u1") < versions.DebianVersion(
                "2.13.1-1%2Bdeb11u1"
            )
        # Decode the version and test:
        assert versions.DebianVersion(
            urllib.parse.unquote("2.12.1-1%2Bdeb11u1")
        ) < versions.DebianVersion(urllib.parse.unquote("2.13.1-1%2Bdeb11u1"))

        # Expect an error when comparing different types.
        with pytest.raises(TypeError):
            assert versions.PypiVersion("0.9") < versions.DebianVersion("0.10")

        # This demonstrates that versions.Version does not correctly compare 0.9 vs. 0.10.
        assert not versions.Version("0.9") < versions.Version("0.10")
        # Use SemverVersion instead as a default fallback version for comparisons.
        assert versions.SemverVersion("0.9") < versions.SemverVersion("0.10")

    def test_univers_version_class(self):
        gem_version = RANGE_CLASS_BY_SCHEMES["gem"].version_class
        assert gem_version == versions.RubygemsVersion

        gem_package = models.Package.objects.create(type="gem", name="sidekiq", version="0.9")
        gem_package_version = RANGE_CLASS_BY_SCHEMES[gem_package.type].version_class
        assert gem_package_version == versions.RubygemsVersion

        deb_version = RANGE_CLASS_BY_SCHEMES["deb"].version_class
        assert deb_version == versions.DebianVersion

        deb_package = models.Package.objects.create(type="deb", name="git", version="2.31.1")
        deb_package_version = RANGE_CLASS_BY_SCHEMES[deb_package.type].version_class
        assert deb_package_version == versions.DebianVersion

        pypi_version = RANGE_CLASS_BY_SCHEMES["pypi"].version_class
        assert pypi_version == versions.PypiVersion

        pypi_package = models.Package.objects.create(type="pypi", name="pyopenssl", version="0.9")
        pypi_package_version = RANGE_CLASS_BY_SCHEMES[pypi_package.type].version_class
        assert pypi_package_version == versions.PypiVersion

        alpine_package = models.Package.objects.create(type="alpine", name="lxml", version="0.9")
        alpine_version = RANGE_CLASS_BY_SCHEMES[alpine_package.type].version_class
        assert alpine_version == versions.AlpineLinuxVersion

    def test_sort_by_version(self):
        list_to_sort = [
            "pkg:npm/sequelize@3.13.1",
            "pkg:npm/sequelize@3.10.1",
            "pkg:npm/sequelize@3.40.1",
            "pkg:npm/sequelize@3.9.1",
        ]

        # Convert list of strings ^ to a list of vulnerablecode Package objects.
        vuln_pkg_list = []
        for package in list_to_sort:
            purl = PackageURL.from_string(package)
            attrs = {k: v for k, v in purl.to_dict().items() if v}
            vulnerablecode_package = models.Package.objects.create(**attrs)
            vuln_pkg_list.append(vulnerablecode_package)

        requesting_package = models.Package.objects.create(
            type="npm",
            name="sequelize",
            version="3.0.0",
        )

        sorted_pkgs = requesting_package.sort_by_version(vuln_pkg_list)
        first_sorted_item = sorted_pkgs[0]

        assert sorted_pkgs[0].purl == "pkg:npm/sequelize@3.9.1"
        assert sorted_pkgs[-1].purl == "pkg:npm/sequelize@3.40.1"

    def test_affecting_vulnerabilities_vulnerabilityqueryset_method(self):
        """
        Return querysets of Vulnerabilities using the VulnerabilityQuerySet affecting_vulnerabilities() method.
        """
        searched_for_package = self.package_pypi_redis_4_1_1

        # Return a queryset of Vulnerabilities that affect this Package.
        this_package_vulnerabilities = (
            searched_for_package.vulnerabilities.affecting_vulnerabilities()
        )

        assert this_package_vulnerabilities[0] == self.vuln_VCID_g2fu_45jw_aaan
        assert this_package_vulnerabilities[1] == self.vuln_VCID_rqe1_dkmg_aaad

        # Return a queryset of Vulnerabilities that affect any Package.
        any_package_vulnerabilities = Vulnerability.objects.affecting_vulnerabilities()

        assert any_package_vulnerabilities[0] == self.vuln_VCID_abcd_efgh_1234
        assert any_package_vulnerabilities[1] == self.vuln_VCID_g2fu_45jw_aaan
        assert any_package_vulnerabilities[2] == self.vuln_VCID_rqe1_dkmg_aaad
        assert any_package_vulnerabilities[3] == self.vuln_VCID_rqe1_dkmg_aaad

        # Return a queryset of distinct Vulnerabilities that affect any Package.
        any_package_vulnerabilities_distinct = (
            Vulnerability.objects.affecting_vulnerabilities().distinct()
        )

        assert any_package_vulnerabilities_distinct[0] == self.vuln_VCID_abcd_efgh_1234
        assert any_package_vulnerabilities_distinct[1] == self.vuln_VCID_g2fu_45jw_aaan
        assert any_package_vulnerabilities_distinct[2] == self.vuln_VCID_rqe1_dkmg_aaad

        # Return a count of the queryset of distinct Vulnerabilities that affect any Package.
        any_package_vulnerabilities_distinct_count = (
            Vulnerability.objects.affecting_vulnerabilities().distinct().count()
        )

        assert any_package_vulnerabilities_distinct_count == 3

        # Return a queryset of all Vulnerabilities, regardless of whether they affect a package.
        all_vulnerabilities = Vulnerability.objects.all()

        assert all_vulnerabilities[0] == self.vuln_VCID_abcd_efgh_1234
        assert all_vulnerabilities[1] == self.vuln_VCID_g2fu_45jw_aaan
        assert all_vulnerabilities[2] == self.vuln_VCID_rqe1_dkmg_aaad
        assert all_vulnerabilities[3] == self.vuln_VCID_wxyz_0000_0000

        # Return a count of the queryset of all Vulnerabilities, regardless of whether they affect a package.
        all_vulnerabilities_count = Vulnerability.objects.all().count()

        assert all_vulnerabilities_count == 4

    def test_affecting_vulnerabilities_package_property_method(self):
        """
        Return a queryset of Vulnerabilities using the Package affecting_vulnerabilities() property
        method.
        """
        searched_for_package = self.package_pypi_redis_4_1_1

        # Return a queryset of Vulnerabilities that affect a specific Package.
        this_package_vulnerabilities = searched_for_package.affecting_vulnerabilities

        assert this_package_vulnerabilities[0] == self.vuln_VCID_g2fu_45jw_aaan
        assert this_package_vulnerabilities[1] == self.vuln_VCID_rqe1_dkmg_aaad

    def test_fixing_vulnerabilities_package_property_method(self):
        """
        Return a queryset of Vulnerabilities using the Package fixing_vulnerabilities() property
        method.
        """
        # Return a queryset of Vulnerabilities that are fixed by a specific Package.
        searched_for_package_redis_4_1_1 = self.package_pypi_redis_4_1_1
        redis_4_1_1_fixing_vulnerabilities = searched_for_package_redis_4_1_1.fixing_vulnerabilities

        assert redis_4_1_1_fixing_vulnerabilities.count() == 0

        searched_for_package_redis_4_3_6 = self.package_pypi_redis_4_3_6
        redis_4_3_6_fixing_vulnerabilities = searched_for_package_redis_4_3_6.fixing_vulnerabilities

        assert redis_4_3_6_fixing_vulnerabilities.count() == 1
        assert redis_4_3_6_fixing_vulnerabilities[0] == self.vuln_VCID_g2fu_45jw_aaan

        searched_for_package_redis_5_0_0b1 = self.package_pypi_redis_5_0_0b1
        redis_5_0_0b1_fixing_vulnerabilities = (
            searched_for_package_redis_5_0_0b1.fixing_vulnerabilities
        )

        assert redis_5_0_0b1_fixing_vulnerabilities.count() == 1
        assert redis_5_0_0b1_fixing_vulnerabilities[0] == self.vuln_VCID_rqe1_dkmg_aaad

    def test_get_affecting_vulnerabilities_package_method(self):
        """
        Return a list of vulnerabilities that affect this package.
        """
        searched_for_package_redis_4_1_1 = self.package_pypi_redis_4_1_1
        redis_4_1_1_affecting_vulnerabilities = (
            searched_for_package_redis_4_1_1.get_affecting_vulnerabilities()
        )

        affecting_vulnerabilities = [
            {
                "vulnerability": self.vuln_VCID_g2fu_45jw_aaan,
                "fixed_by_purl": [],
                "fixed_by_purl_vulnerabilities": [],
                "fixed_by_package_details": [
                    {
                        "fixed_by_purl": PackageURL(
                            type="pypi",
                            namespace=None,
                            name="redis",
                            version="4.3.6",
                            qualifiers={},
                            subpath=None,
                        ),
                        "fixed_by_purl_vulnerabilities": [self.vuln_VCID_rqe1_dkmg_aaad],
                    }
                ],
            },
            {
                "vulnerability": self.vuln_VCID_rqe1_dkmg_aaad,
                "fixed_by_purl": [],
                "fixed_by_purl_vulnerabilities": [],
                "fixed_by_package_details": [
                    {
                        "fixed_by_purl": PackageURL(
                            type="pypi",
                            namespace=None,
                            name="redis",
                            version="5.0.0b1",
                            qualifiers={},
                            subpath=None,
                        ),
                        "fixed_by_purl_vulnerabilities": [],
                    }
                ],
            },
        ]

        assert redis_4_1_1_affecting_vulnerabilities == affecting_vulnerabilities

    def test_get_non_vulnerable_versions(self):
        redis_next, redis_later = self.package_pypi_redis_4_1_1.get_non_vulnerable_versions()
        assert redis_next.version == "5.0.0b1"
        assert redis_later.version == "5.0.0b1"

    def test_version_class_and_current_version(self):
        package = self.package_pypi_redis_4_1_1

        package_version_class = RANGE_CLASS_BY_SCHEMES[package.type].version_class

        assert package_version_class == versions.PypiVersion
        assert package.current_version == package_version_class(string="4.1.1")
        assert str(package.current_version) == "4.1.1"

    def test_get_fixed_by_package_versions(self):
        searched_for_package_redis_4_1_1 = self.package_pypi_redis_4_1_1

        fixed_by_package_versions = Package.objects.get_fixed_by_package_versions(
            searched_for_package_redis_4_1_1, fix=True
        )

        all_package_versions = Package.objects.get_fixed_by_package_versions(
            searched_for_package_redis_4_1_1, fix=False
        )

        assert fixed_by_package_versions[0] == self.package_pypi_redis_4_3_6
        assert fixed_by_package_versions[1] == self.package_pypi_redis_5_0_0b1
        assert fixed_by_package_versions.count() == 2

        assert all_package_versions[0] == self.package_pypi_redis_4_1_1
        assert all_package_versions[1] == self.package_pypi_redis_4_3_6
        assert all_package_versions[2] == self.package_pypi_redis_5_0_0b1
        assert all_package_versions.count() == 3
