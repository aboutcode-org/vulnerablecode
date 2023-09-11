#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
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

from vulnerabilities import models
from vulnerabilities.models import Alias
from vulnerabilities.models import Package


class TestVulnerabilityModel(TestCase):
    def test_generate_vulcoid_given_timestamp_object(self):
        timestamp_object = datetime(2021, 1, 1, 11, 12, 13, 2000)
        expected_vulcoid = "VULCOID-20210101-1112-13002000"
        found_vulcoid = models.Vulnerability.generate_vulcoid(timestamp_object)
        assert expected_vulcoid == found_vulcoid

    def test_generate_vulcoid(self):
        expected_vulcoid = "VULCOID-20210101-1112-13000000"
        with freeze_time("2021-01-01 11:12:13.000000"):
            found_vulcoid = models.Vulnerability.generate_vulcoid()
        assert expected_vulcoid == found_vulcoid

    @pytest.mark.django_db
    def test_vulnerability_save_with_vulnerability_id(self):
        models.Vulnerability(vulnerability_id="CVE-2020-7965").save()
        assert models.Vulnerability.objects.filter(vulnerability_id="CVE-2020-7965").count() == 1

    @pytest.mark.django_db
    def test_vulnerability_save_without_vulnerability_id(self):
        assert (
            models.Vulnerability.objects.filter(
                vulnerability_id="VULCOID-20210101-1112-13000000"
            ).count()
            == 0
        )

        with freeze_time("2021-01-01 11:12:13.000000"):
            models.Vulnerability(vulnerability_id="").save()
            assert (
                models.Vulnerability.objects.filter(
                    vulnerability_id="VULCOID-20210101-1112-13000000"
                ).count()
                == 1
            )

    def test_cwe_not_present_in_weaknesses_db(self):
        w1 = models.Weakness.objects.create(name="189")
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

        prv1 = models.PackageRelatedVulnerability.objects.create(
            patched_package=p2, package=p1, vulnerability=v1
        )

        assert p1.vulnerabilities.all().count() == 1
        assert p1.resolved_vulnerabilities.all().count() == 0
        assert p1.vulnerabilities.all()[0] == v1

        assert p2.vulnerabilities.all().count() == 0
        assert p2.resolved_vulnerabilities.all().count() == 1
        assert p2.resolved_vulnerabilities.all()[0] == v1

    def test_vulnerability_package(self):
        p1 = models.Package.objects.create(type="deb", name="git", version="2.30.1")
        p2 = models.Package.objects.create(type="deb", name="git", version="2.31.1")
        v1 = models.Vulnerability.objects.create(vulnerability_id="CVE-123-2002")

        prv1 = models.PackageRelatedVulnerability.objects.create(
            patched_package=p2, package=p1, vulnerability=v1
        )

        assert v1.vulnerable_packages.all().count() == 1
        assert v1.patched_packages.all().count() == 1

        assert v1.vulnerable_packages.all()[0] == p1
        assert v1.patched_packages.all()[0] == p2


@pytest.mark.django_db
class TestPackageModel(TestCase):
    def setUp(self):
        # ZAP: 2023-09-08 Friday 17:40:36.  Let's start over with a focused package/vuln/fix group we know from the DB/UI testing: pkg:pypi/redis@4.1.1
        # It has 2 non-vulns versions, both the same: 5.0.0b1
        # The first of its two vulns is VCID-g2fu-45jw-aaan (aliases: CVE-2023-28858 and GHSA-24wv-mv5m-xv4h), fixed by 4.3.6 w/1 vuln of its own
        # The second is VCID-rqe1-dkmg-aaad (aliases: CVE-2023-28859 and GHSA-8fww-64cx-x8p5), fixed by 5.0.0b1 w/ 0 vulns of its own

        # pkg
        self.package_pypi_redis_4_1_1 = models.Package.objects.create(
            type="pypi",
            namespace="",
            name="redix",
            version="4.1.1",
            qualifiers={},
            subpath="",
        )

        # vuln
        self.vuln_VCID_g2fu_45jw_aaan = models.Vulnerability.objects.create(
            summary="This is VCID-g2fu-45jw-aaan",
            vulnerability_id="VCID-g2fu-45jw-aaan",
        )

        # relationship
        models.PackageRelatedVulnerability.objects.create(
            package=self.package_pypi_redis_4_1_1,
            vulnerability=self.vuln_VCID_g2fu_45jw_aaan,
            fix=False,
        )

        # aliases
        Alias.objects.create(alias="CVE-2023-28858", vulnerability=self.vuln_VCID_g2fu_45jw_aaan)
        Alias.objects.create(
            alias="GHSA-24wv-mv5m-xv4h", vulnerability=self.vuln_VCID_g2fu_45jw_aaan
        )

        # ZAP: Need fix for above vuln

        # vuln
        self.vuln_VCID_rqe1_dkmg_aaad = models.Vulnerability.objects.create(
            summary="This is VCID-rqe1-dkmg-aaad",
            vulnerability_id="VCID-rqe1-dkmg-aaad",
        )

        # relationship
        models.PackageRelatedVulnerability.objects.create(
            package=self.package_pypi_redis_4_1_1,
            vulnerability=self.vuln_VCID_rqe1_dkmg_aaad,
            fix=False,
        )

        # aliases
        Alias.objects.create(alias="CVE-2023-28859", vulnerability=self.vuln_VCID_rqe1_dkmg_aaad)
        Alias.objects.create(
            alias="GHSA-8fww-64cx-x8p5", vulnerability=self.vuln_VCID_rqe1_dkmg_aaad
        )

        # ZAP: Need fix for above vuln

        # ZAP: Need non-vuln version(s)

        # ========================================================

        # ========================================================

        # ZAP: Not sure we want to keep any of this.
        self.vuln1 = models.Vulnerability.objects.create(
            summary="test-vuln1",
            vulnerability_id="VCID-123",
        )
        self.vuln2 = models.Vulnerability.objects.create(
            summary="test-vuln2",
            vulnerability_id="VCID-456",
        )

        # Create a vuln of its own for the fixed_by_package
        self.vuln3 = models.Vulnerability.objects.create(
            summary="test-vuln-not-used-anywhere",
            vulnerability_id="VCID-000",
        )

        self.vulnerablecode_package = models.Package.objects.create(
            type="maven",
            namespace="com.fasterxml.jackson.core",
            name="jackson-databind",
            version="2.13.1",
            qualifiers={},
            subpath="",
        )

        self.fixed_by_package = models.Package.objects.create(
            type="maven",
            namespace="com.fasterxml.jackson.core",
            name="jackson-databind",
            version="2.13.2",
            qualifiers={},
            subpath="",
        )

        self.backport_fixed_by_package = models.Package.objects.create(
            type="maven",
            namespace="com.fasterxml.jackson.core",
            name="jackson-databind",
            version="2.12.6.1",
            qualifiers={},
            subpath="",
        )

        self.non_vulnerable_package = models.Package.objects.create(
            type="maven",
            namespace="com.fasterxml.jackson.core",
            name="jackson-databind",
            version="2.14.0-rc1",
            qualifiers={},
            subpath="",
        )

        models.PackageRelatedVulnerability.objects.create(
            package=self.vulnerablecode_package,
            vulnerability=self.vuln1,
            fix=False,
        )

        models.PackageRelatedVulnerability.objects.create(
            package=self.vulnerablecode_package,
            vulnerability=self.vuln2,
            fix=False,
        )

        # Create a fixed_by package for vuln1
        models.PackageRelatedVulnerability.objects.create(
            package=self.fixed_by_package,
            vulnerability=self.vuln1,
            fix=True,
        )

        # Add backport_fixed_by_package as a fixed_by for vuln1 -- but this should be excluded because its version is less than the affected package's version.
        models.PackageRelatedVulnerability.objects.create(
            package=self.backport_fixed_by_package,
            vulnerability=self.vuln1,
            fix=True,
        )

        # Create a vuln of its own for the fixed_by_packagefixed_by package for vuln1
        models.PackageRelatedVulnerability.objects.create(
            package=self.fixed_by_package,
            vulnerability=self.vuln3,
            fix=False,
        )

        # Create additional Package objects with various versions to test the major version identification and comparison process.

        self.pypi_setuptools_affected_package = models.Package.objects.create(
            type="pypi",
            namespace="",
            name="setuptools",
            version="40.8.0",
            qualifiers={},
            subpath="",
        )

        self.pypi_setuptools_fixed_closest_and_latest_non_vulnerable_packages = (
            models.Package.objects.create(
                type="pypi",
                namespace="",
                name="setuptools",
                version="65.5.1",
                qualifiers={},
                subpath="",
            )
        )

        # pkg:maven/org.eclipse.jetty/jetty-util@9.3.20.v20170531

        # from the string
        jetty_util_purl = PackageURL.from_string(
            "pkg:maven/org.eclipse.jetty/jetty-util@9.3.20.v20170531"
        )

        # # convert purl to dict
        # jetty_util_purl_to_dict = jetty_util_purl.to_dict()
        # # This will avoid the IntegrityError:
        # if jetty_util_purl_to_dict.get("qualifiers") is None:
        #     jetty_util_purl_to_dict["qualifiers"] = {}
        # if jetty_util_purl_to_dict.get("subpath") is None:
        #     jetty_util_purl_to_dict["subpath"] = ""

        # This takes the place of the 2 preceding bits -- uses purl_to_dict() rather than just to_dict()
        jetty_util_purl_to_dict = models.purl_to_dict(jetty_util_purl)

        # convert dict to Package
        # This needs self, right?
        self.maven_jetty_util_affected_package = models.Package.objects.create(
            type=jetty_util_purl_to_dict.get("type"),
            namespace=jetty_util_purl_to_dict.get("namespace"),
            name=jetty_util_purl_to_dict.get("name"),
            version=jetty_util_purl_to_dict.get("version"),
            qualifiers=jetty_util_purl_to_dict.get("qualifiers"),
            subpath=jetty_util_purl_to_dict.get("subpath"),
        )

        # using the create method
        # self.maven_jetty_util_affected_package = models.Package.objects.create(
        #     type="maven",
        #     namespace="org.eclipse.jetty",
        #     name="jetty-util",
        #     version="9.3.20.v20170531",
        #     qualifiers={},
        #     subpath="",
        # )
        # pkg:maven/org.eclipse.jetty/jetty-util@9.4.39.v20210325
        self.maven_jetty_util_fixed_package = models.Package.objects.create(
            type="maven",
            namespace="org.eclipse.jetty",
            name="jetty-util",
            version="9.4.39.v20210325",
            qualifiers={},
            subpath="",
        )
        # pkg:maven/org.eclipse.jetty/jetty-util@11.0.14
        self.maven_jetty_util_closest_and_latest_non_vulnerable_packages = (
            models.Package.objects.create(
                type="maven",
                namespace="org.eclipse.jetty",
                name="jetty-util",
                version="11.0.14",
                qualifiers={},
                subpath="",
            )
        )

    # 2023-09-08 Friday 21:24:54.  New experiment
    def test_explore_packages(self):
        print("\nself.package_pypi_redis_4_1_1 = {}\n".format(self.package_pypi_redis_4_1_1))

        print(
            "\nself.package_pypi_redis_4_1_1.package_url = {}\n".format(
                self.package_pypi_redis_4_1_1.package_url
            )
        )

        print(
            "\nself.package_pypi_redis_4_1_1.plain_package_url = {}\n".format(
                self.package_pypi_redis_4_1_1.plain_package_url
            )
        )

        print(
            "\nself.package_pypi_redis_4_1_1.purl = {}\n".format(self.package_pypi_redis_4_1_1.purl)
        )

        print(
            "\nself.package_pypi_redis_4_1_1.affected_by = {}\n".format(
                self.package_pypi_redis_4_1_1.affected_by
            )
        )

        for vuln in self.package_pypi_redis_4_1_1.affected_by:
            print(vuln)
            print(vuln.summary)
            print("")

        print(
            "\nself.package_pypi_redis_4_1_1.fixing = {}\n".format(
                self.package_pypi_redis_4_1_1.fixing
            )
        )

        print(
            "\nself.package_pypi_redis_4_1_1.get_absolute_url() = {}\n".format(
                self.package_pypi_redis_4_1_1.get_absolute_url()
            )
        )

    # ZAP: 2023-09-08 Friday 18:37:13.  Need to revise this after adding new pkgs, vulns, aliases above.
    def test_get_vulnerable_packages(self):
        vuln_packages = Package.objects.vulnerable()
        print("\nvuln_packages = {}\n".format(vuln_packages))
        # assert vuln_packages.count() == 3
        # 2023-09-08 Friday 16:59:33.  Update given today's additions etc.
        assert vuln_packages.count() == 5
        # assert vuln_packages.distinct().count() == 2
        assert vuln_packages.distinct().count() == 3

        first_vulnerable_package = vuln_packages.distinct()[0]
        matching_fixed_packages = first_vulnerable_package.get_fixed_packages(
            first_vulnerable_package
        )
        first_fixed_by_package = matching_fixed_packages[0]

        assert (
            first_vulnerable_package.purl
            == "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1"
        )
        assert len(matching_fixed_packages) == 2
        assert (
            first_fixed_by_package.purl
            == "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.12.6.1"
        )

        # purl_dict = {
        #     "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1",
        #     "vulnerabilities": [
        #         {
        #             "vulnerability": "VCID-123",
        #             "closest_fixed_by": {
        #                 "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2",
        #                 "type": "maven",
        #                 "namespace": "com.fasterxml.jackson.core",
        #                 "name": "jackson-databind",
        #                 "version": "2.13.2",
        #                 "qualifiers": {},
        #                 "subpath": "",
        #             },
        #             "closest_fixed_by_vulnerabilities": [{"vuln_id": "VCID-000"}],
        #         },
        #         {
        #             "vulnerability": "VCID-456",
        #             "closest_fixed_by": {},
        #             "closest_fixed_by_vulnerabilities": [],
        #         },
        #     ],
        #     "closest_non_vulnerable": {},
        #     "latest_non_vulnerable": {},
        # }

        # purl_dict = {
        #     "purl": PackageURL(
        #         type="maven",
        #         namespace="com.fasterxml.jackson.core",
        #         name="jackson-databind",
        #         version="2.13.1",
        #         qualifiers={},
        #         subpath=None,
        #     ),
        #     "closest_non_vulnerable": PackageURL(
        #         type="maven",
        #         namespace="com.fasterxml.jackson.core",
        #         name="jackson-databind",
        #         version="2.14.0-rc1",
        #         qualifiers={},
        #         subpath=None,
        #     ),
        #     "latest_non_vulnerable": PackageURL(
        #         type="maven",
        #         namespace="com.fasterxml.jackson.core",
        #         name="jackson-databind",
        #         version="2.14.0-rc1",
        #         qualifiers={},
        #         subpath=None,
        #     ),
        #     "vulnerabilities": [
        #         {
        #             "vulnerability": "<Vulnerability: VCID-123>",
        #             "fixed_by_purl": PackageURL(
        #                 type="maven",
        #                 namespace="com.fasterxml.jackson.core",
        #                 name="jackson-databind",
        #                 version="2.13.2",
        #                 qualifiers={},
        #                 subpath=None,
        #             ),
        #             "fixed_by_purl_vulnerabilities": ["<Vulnerability: " "VCID-000>"],
        #         },
        #         {
        #             "vulnerability": "<Vulnerability: VCID-456>",
        #             "fixed_by_purl": None,
        #             "fixed_by_purl_vulnerabilities": [],
        #         },
        #     ],
        # }

        print("\nfirst_vulnerable_package.purl = {}\n".format(first_vulnerable_package.purl))

        print("\nfirst_vulnerable_package = {}\n".format(first_vulnerable_package))

        assert (
            first_vulnerable_package.purl
            == "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1"
        )

        # assert (
        #     first_vulnerable_package
        #     # == "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1"
        #     == "<Package: pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1>"
        # )

        purl_string = "pkg:pypi/redis@4.1.1"
        purl = PackageURL.from_string(purl_string)
        purl_to_dict = purl.to_dict()

        # For namespace, version, qualifiers and subpath, we need to add the or * to avoid an IntegrityError, e.g., django.db.utils.IntegrityError: null value in column "subpath" violates not-null constraint
        vulnerablecode_package = models.Package.objects.create(
            type=purl_to_dict.get("type"),
            namespace=purl_to_dict.get("namespace") or "",
            name=purl_to_dict.get("name"),
            version=purl_to_dict.get("version") or "",
            qualifiers=purl_to_dict.get("qualifiers") or {},
            subpath=purl_to_dict.get("subpath") or "",
        )

        print("\nvulnerablecode_package = {}\n".format(vulnerablecode_package))
        print(
            "\nvulnerablecode_package.fixed_package_details = {}\n".format(
                vulnerablecode_package.fixed_package_details
            )
        )

        # ===============================

        # # Dictionary with class values
        # my_dict = {"obj1": MyClass(1), "obj2": MyClass(2)}

        # # Print the dictionary
        # print(my_dict)

        # assert vuln_packages.distinct()[0].fixed_package_details == purl_dict

        # banana = {'purl': PackageURL(type='maven', namespace='com.fasterxml.jackson.core', name='jackson-databind', version='2.13.1', qualifiers={}, subpath=None), 'closest_non_vulnerable': PackageURL(type='maven', namespace='com.fasterxml.jackson.core', name='jackson-databind', version='2.14.0-rc1', qualifiers={}, subpath=None), 'latest_non_vulnerable': PackageURL(type='maven', namespace='com.fasterxml.jackson.core', name='jackson-databind', version='2.14.0-rc1', qualifiers={}, subpath=None), 'vulnerabilities': [{'vulnerability': <Vulnerability: VCID-123>, 'fixed_by_purl': PackageURL(type='maven', namespace='com.fasterxml.jackson.core', name='jackson-databind', version='2.13.2', qualifiers={}, subpath=None), 'fixed_by_purl_vulnerabilities': [<Vulnerability: VCID-000>]}, {'vulnerability': <Vulnerability: VCID-456>, 'fixed_by_purl': None, 'fixed_by_purl_vulnerabilities': []}]}

        # print('\nbanana = {}\n'.format(banana))

        # assert vuln_packages.distinct()[0].`fixed_package_details` == banana

        print(
            "\nvuln_packages.distinct()[0].fixed_package_details = {}\n".format(
                vuln_packages.distinct()[0].fixed_package_details
            )
        )

        # print(vuln_packages.distinct()[0]["vulnerabilities"].fixed_package_details)  # Error: TypeError: 'Package' object is not subscriptable

        print(
            "\ntype(vuln_packages.distinct()[0].fixed_package_details) = {}\n".format(
                type(vuln_packages.distinct()[0].fixed_package_details)
            )
        )

        print(
            '\nvuln_packages.distinct()[0].fixed_package_details.get("purl") = {}\n'.format(
                vuln_packages.distinct()[0].fixed_package_details.get("purl")
            )
        )

        print(
            '\nvuln_packages.distinct()[0].fixed_package_details["purl"] = {}\n'.format(
                vuln_packages.distinct()[0].fixed_package_details["purl"]
            )
        )

        print(
            '\nvuln_packages.distinct()[0].fixed_package_details["vulnerabilities"] = {}\n'.format(
                vuln_packages.distinct()[0].fixed_package_details["vulnerabilities"]
            )
        )

        print(
            '\nvuln_packages.distinct()[0].fixed_package_details["vulnerabilities"][0] = {}\n'.format(
                vuln_packages.distinct()[0].fixed_package_details["vulnerabilities"][0]
            )
        )

        print(
            '\nvuln_packages.distinct()[0].fixed_package_details["vulnerabilities"][0]["vulnerability"] = {}\n'.format(
                vuln_packages.distinct()[0].fixed_package_details["vulnerabilities"][0][
                    "vulnerability"
                ]
            )
        )

        print("")

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

    # # ZAP: 2023-09-07 Thursday 20:05:40.  This has served its purpose and can be removed after a last close look.
    # def test_string_to_purl_to_dict_to_package(self):
    #     # Convert a PURL string to a PURL to a dictionary to a VulnerableCode Package, i.e.,
    #     # a <class 'vulnerabilities.models.Package'>.

    #     # Convert a PURL string to a PURL.
    #     purl_string = "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.31"
    #     purl = PackageURL.from_string(purl_string)

    #     assert type(purl) == PackageURL
    #     assert purl.type == "maven"
    #     assert purl.qualifiers == {}
    #     assert purl.subpath == None

    #     # Convert the PURL to a dictionary.
    #     # ALERT: 2023-08-15 Tuesday 13:18:09.  What about using the function 'def purl_to_dict(purl: PackageURL)'?  Confusingly similar name but it seems designed to address the issue raised here (and looks useful for passing the data to the Jinja2 template).
    #     # It appears that this step is where the unwanted None values are created for qualifiers and
    #     # subpath when the PURL does not already contain values for those attributes.
    #     purl_to_dict = purl.to_dict()

    #     assert purl_to_dict == {
    #         "type": "maven",
    #         "namespace": "org.apache.tomcat.embed",
    #         "name": "tomcat-embed-core",
    #         "version": "9.0.31",
    #         "qualifiers": None,
    #         "subpath": None,
    #     }
    #     assert purl_to_dict.get("qualifiers") == None
    #     assert purl_to_dict.get("subpath") == None

    #     # Convert the dictionary to a VulnerableCode Package, i.e.,
    #     # a <class 'vulnerabilities.models.Package'>

    #     # If subpath is None we get error: django.db.utils.IntegrityError: null value in column
    #     # "subpath" violates not-null constraint -- need to convert value from None to empty string.
    #     # Similar issue with qualifiers, which must be converted from None to {}.

    #     # I've structured the following in this way because trying instead to use
    #     # "with pytest.raises(IntegrityError):" will throw the error
    #     # django.db.transaction.TransactionManagementError: An error occurred in the current
    #     # transaction. You can't execute queries until the end of the 'atomic' block.

    #     try:
    #         with transaction.atomic():
    #             vulnerablecode_package = models.Package.objects.create(
    #                 type=purl_to_dict.get("type"),
    #                 namespace=purl_to_dict.get("namespace"),
    #                 name=purl_to_dict.get("name"),
    #                 version=purl_to_dict.get("version"),
    #                 qualifiers=purl_to_dict.get("qualifiers"),
    #                 subpath=purl_to_dict.get("subpath"),
    #             )
    #     except IntegrityError:
    #         print("\nAs expected, an IntegrityError has occurred.\n")

    #     # This will avoid the IntegrityError:
    #     if purl_to_dict.get("qualifiers") is None:
    #         purl_to_dict["qualifiers"] = {}
    #     if purl_to_dict.get("subpath") is None:
    #         purl_to_dict["subpath"] = ""

    #     # Check the qualifiers and subpath values again.
    #     assert purl_to_dict.get("qualifiers") == {}
    #     assert purl_to_dict.get("subpath") == ""

    #     vulnerablecode_package = models.Package.objects.create(
    #         type=purl_to_dict.get("type"),
    #         namespace=purl_to_dict.get("namespace"),
    #         name=purl_to_dict.get("name"),
    #         version=purl_to_dict.get("version"),
    #         qualifiers=purl_to_dict.get("qualifiers"),
    #         subpath=purl_to_dict.get("subpath"),
    #     )

    #     assert type(vulnerablecode_package) == models.Package
    #     assert (
    #         vulnerablecode_package.purl
    #         == "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.31"
    #     )
    #     assert vulnerablecode_package.qualifiers == {}
    #     assert vulnerablecode_package.subpath == ""

    # # ZAP: 2023-09-07 Thursday 20:32:35.  Ditch this, right?
    # def test_compare_package_major_versions(self):
    #     # Convert a PURL string to a PURL to a dictionary to a VulnerableCode Package, i.e.,
    #     # a <class 'vulnerabilities.models.Package'>.

    #     # Convert a PURL string to a PURL.
    #     purl_string = "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.31"
    #     purl = PackageURL.from_string(purl_string)

    #     assert type(purl) == PackageURL
    #     assert purl.type == "maven"
    #     assert purl.qualifiers == {}
    #     assert purl.subpath == None

    #     print("\npurl_string = {}".format(purl_string))

    #     print("\npurl = {}".format(purl))

    #     print("\nHello VulnerableCode!\n")

    #     all_packages = Package.objects
    #     print("\nPackage.objects = {}\n".format(Package.objects))
    #     print("\nall_packages.distinct() = {}\n".format(all_packages.distinct()))
    #     print("\nall_packages.distinct()[0] = {}\n".format(all_packages.distinct()[0]))

    #     for pkg in all_packages.distinct():
    #         print(PackageURL.from_string(pkg.purl))

    #     print("")
