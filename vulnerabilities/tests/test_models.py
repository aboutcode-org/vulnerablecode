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

    def test_get_vulnerable_packages(self):
        vuln_packages = Package.objects.vulnerable()
        assert vuln_packages.count() == 3
        assert vuln_packages.distinct().count() == 2

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

        purl_dict = {
            "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.1",
            "vulnerabilities": [
                {
                    "vulnerability": "VCID-123",
                    "closest_fixed_by": {
                        "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.2",
                        "type": "maven",
                        "namespace": "com.fasterxml.jackson.core",
                        "name": "jackson-databind",
                        "version": "2.13.2",
                        "qualifiers": {},
                        "subpath": "",
                    },
                    "closest_fixed_by_vulnerabilities": [{"vuln_id": "VCID-000"}],
                },
                {
                    "vulnerability": "VCID-456",
                    "closest_fixed_by": {},
                    "closest_fixed_by_vulnerabilities": [],
                },
            ],
            "closest_non_vulnerable": {},
            "latest_non_vulnerable": {},
        }

        assert vuln_packages.distinct()[0].fixed_package_details == purl_dict

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

    def test_string_to_purl_to_dict_to_package(self):
        # Convert a PURL string to a PURL to a dictionary to a VulnerableCode Package, i.e.,
        # a <class 'vulnerabilities.models.Package'>.

        # Convert a PURL string to a PURL.
        purl_string = "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.31"
        purl = PackageURL.from_string(purl_string)

        assert type(purl) == PackageURL
        assert purl.type == "maven"
        assert purl.qualifiers == {}
        assert purl.subpath == None

        # Convert the PURL to a dictionary.
        # ALERT: 2023-08-15 Tuesday 13:18:09.  What about using the function 'def purl_to_dict(purl: PackageURL)'?  Confusingly similar name but it seems designed to address the issue raised here (and looks useful for passing the data to the Jinja2 template).
        # It appears that this step is where the unwanted None values are created for qualifiers and
        # subpath when the PURL does not already contain values for those attributes.
        purl_to_dict = purl.to_dict()

        assert purl_to_dict == {
            "type": "maven",
            "namespace": "org.apache.tomcat.embed",
            "name": "tomcat-embed-core",
            "version": "9.0.31",
            "qualifiers": None,
            "subpath": None,
        }
        assert purl_to_dict.get("qualifiers") == None
        assert purl_to_dict.get("subpath") == None

        # Convert the dictionary to a VulnerableCode Package, i.e.,
        # a <class 'vulnerabilities.models.Package'>

        # If subpath is None we get error: django.db.utils.IntegrityError: null value in column
        # "subpath" violates not-null constraint -- need to convert value from None to empty string.
        # Similar issue with qualifiers, which must be converted from None to {}.

        # I've structured the following in this way because trying instead to use
        # "with pytest.raises(IntegrityError):" will throw the error
        # django.db.transaction.TransactionManagementError: An error occurred in the current
        # transaction. You can't execute queries until the end of the 'atomic' block.

        try:
            with transaction.atomic():
                vulnerablecode_package = models.Package.objects.create(
                    type=purl_to_dict.get("type"),
                    namespace=purl_to_dict.get("namespace"),
                    name=purl_to_dict.get("name"),
                    version=purl_to_dict.get("version"),
                    qualifiers=purl_to_dict.get("qualifiers"),
                    subpath=purl_to_dict.get("subpath"),
                )
        except IntegrityError:
            print("\nAs expected, an IntegrityError has occurred.\n")

        # This will avoid the IntegrityError:
        if purl_to_dict.get("qualifiers") is None:
            purl_to_dict["qualifiers"] = {}
        if purl_to_dict.get("subpath") is None:
            purl_to_dict["subpath"] = ""

        # Check the qualifiers and subpath values again.
        assert purl_to_dict.get("qualifiers") == {}
        assert purl_to_dict.get("subpath") == ""

        vulnerablecode_package = models.Package.objects.create(
            type=purl_to_dict.get("type"),
            namespace=purl_to_dict.get("namespace"),
            name=purl_to_dict.get("name"),
            version=purl_to_dict.get("version"),
            qualifiers=purl_to_dict.get("qualifiers"),
            subpath=purl_to_dict.get("subpath"),
        )

        assert type(vulnerablecode_package) == models.Package
        assert (
            vulnerablecode_package.purl
            == "pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.31"
        )
        assert vulnerablecode_package.qualifiers == {}
        assert vulnerablecode_package.subpath == ""
