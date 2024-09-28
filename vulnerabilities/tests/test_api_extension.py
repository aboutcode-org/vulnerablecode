#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path

from pytest import fixture
from pytest import mark

from vulnerabilities.api_extension import V2VulnerabilityReferenceSerializer
from vulnerabilities.api_extension import V2VulnerabilitySeveritySerializer
from vulnerabilities.models import Alias
from vulnerabilities.models import Package
from vulnerabilities.models import PackageRelatedVulnerability
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.models import Weakness
from vulnerabilities.tests.test_export import vulnerability_severity

TEST_DATA_DIR = Path(__file__).parent / "test_data" / "apiv2"

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


@mark.django_db
def test_V2VulnerabilityReferenceSerializer(vulnerability_reference):
    results = V2VulnerabilityReferenceSerializer(instance=vulnerability_reference).data
    expected = {"reference_url": "https://..", "reference_id": "fake", "reference_type": ""}
    assert expected == results


@mark.django_db
def test_V2VulnerabilitySeveritySerializer(vulnerability_severity):
    results = V2VulnerabilitySeveritySerializer(instance=vulnerability_severity).data
    expected = {
        "published_at": None,
        "reference": {"reference_id": "fake", "reference_type": "", "reference_url": "https://.."},
        "score": "7.0",
        "scoring_elements": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "scoring_system": "cvssv3_vector",
    }

    assert expected == results

    # purls_file = hashid.get_package_purls_yml_file_path(purl=PURL)
    # results_pkgpurls = tmp_path / purls_file
    # expected_pkgpurls = TEST_DATA_DIR / purls_file
    # check_results_and_expected_files(results_pkgpurls, expected_pkgpurls)
