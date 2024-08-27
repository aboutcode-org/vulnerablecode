#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from io import StringIO
from pathlib import Path
from unittest import TestCase

from django.core.management import call_command
from django.core.management.base import CommandError
from pytest import fixture
from pytest import mark
from pytest import raises

from aboutcode import hashid
from vulnerabilities.models import Alias
from vulnerabilities.models import Package
from vulnerabilities.models import PackageRelatedVulnerability
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.models import Weakness
from vulnerabilities.tests.util_tests import check_results_and_expected_files

TEST_DATA_DIR = Path(__file__).parent / "test_data" / "export_command"

VCID = "VCID-pst6-b358-aaap"
PURL = "pkg:generic/nginx/test@2"


@fixture
def package(db):
    return Package.objects.from_purl(PURL)


@fixture
def vulnerability_reference():
    return VulnerabilityReference.objects.create(reference_id="fake", url=f"https://..")


@fixture
def vulnerability_severity(vulnerability_reference):
    return VulnerabilitySeverity.objects.create(
        scoring_system="cvssv3_vector",
        value="7.0",
        scoring_elements="CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        reference_id=vulnerability_reference.id,
    )


@fixture
def vulnerability(db, vulnerability_reference, vulnerability_severity):
    vulnerability = Vulnerability.objects.create(vulnerability_id=VCID, summary="test-vuln")
    Alias.objects.create(alias=f"CVE-xxx-xxx-xx", vulnerability=vulnerability)

    VulnerabilityRelatedReference.objects.create(
        reference=vulnerability_reference,
        vulnerability=vulnerability,
    )

    weakness = Weakness.objects.create(cwe_id=15)
    vulnerability.weaknesses.add(weakness)

    return vulnerability


@fixture
def package_related_vulnerability(db, package, vulnerability):
    PackageRelatedVulnerability.objects.create(
        package=package,
        vulnerability=vulnerability,
        fix=False,
    )
    return package


class TestExportCommand(TestCase):
    def test_missing_path(self):
        with raises(CommandError) as cm:
            call_command("export", stdout=StringIO())

        err = str(cm)
        assert "Error: the following arguments are required: path" in err

    @mark.django_db
    def test_bad_path_fail_error(self):
        with raises(CommandError) as cm:
            call_command("export", "/bad path", stdout=StringIO())

        err = str(cm)
        assert "Enter a valid directory path" in err


@mark.django_db
def test_run_export_command(
    tmp_path,
    package_related_vulnerability,
    vulnerability_reference,
    vulnerability_severity,
):

    call_command("export", tmp_path, stdout=StringIO())

    vcid_file = hashid.get_vcid_yml_file_path(vcid=VCID)
    results_vuln = tmp_path / vcid_file
    expected_vuln = TEST_DATA_DIR / vcid_file
    check_results_and_expected_files(results_vuln, expected_vuln)

    vulns_file = hashid.get_package_vulnerabilities_yml_file_path(purl=PURL)
    results_pkgvulns = tmp_path / vulns_file
    expected_pkgvulns = TEST_DATA_DIR / vulns_file
    check_results_and_expected_files(results_pkgvulns, expected_pkgvulns)

    purls_file = hashid.get_package_purls_yml_file_path(purl=PURL)
    results_pkgpurls = tmp_path / purls_file
    expected_pkgpurls = TEST_DATA_DIR / purls_file
    check_results_and_expected_files(results_pkgpurls, expected_pkgpurls)
