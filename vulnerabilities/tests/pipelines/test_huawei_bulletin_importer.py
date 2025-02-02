#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from pathlib import Path
from unittest.mock import patch

import pytest
from bs4 import BeautifulSoup
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import GENERIC
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "huawei")

def normalize_version_range(version_str):
    """Quick helper to fix version string format"""
    if not version_str.startswith('vers:generic/='):
        version = version_str.split('/')[-1]
        return f'vers:generic/={version}' 
    return version_str

def test_to_advisory_data():
    """Main test for parsing the bullitin data"""
    with open(os.path.join(TEST_DATA, "huawei-test.html")) as f:
        mock_response = BeautifulSoup(f.read(), features="html.parser")
        
    expected_file = os.path.join(TEST_DATA, "huawei-expected.json")

    with open(expected_file) as f:
        import json
        expected = json.load(f)
    with patch("requests.get") as mock_response_get:
        mock_response_get.return_value.text = mock_response
        from vulnerabilities.pipelines.huawei_bulletin_importer import HuaweiBulletinImporterPipeline
        
        pipeline = HuaweiBulletinImporterPipeline()
        pipeline.raw_data = mock_response
        results = [data.to_dict() for data in pipeline.collect_advisories()]

        for result, exp in zip(sorted(results, key=lambda x: x['aliases'][0]), 
                             sorted(expected, key=lambda x: x['aliases'][0])):
            assert result['aliases'] == exp['aliases']  
            assert result['summary'] == exp['summary']
            assert len(result['affected_packages']) == len(exp['affected_packages'])
            for r_pkg, e_pkg in zip(sorted(result['affected_packages'], key=lambda x: x['affected_version_range']),
                sorted(exp['affected_packages'], key=lambda x: x['affected_version_range'])):
                assert normalize_version_range(r_pkg['affected_version_range']) == normalize_version_range(e_pkg['affected_version_range'])
                assert r_pkg['package']['name'] == e_pkg['package']['name']
                assert r_pkg['package']['type'] == e_pkg['package']['type']

test_cases = [
    (
        {
            "cve_id": "CVE-2024-45449",
            "description": "Permission verification vulnerability", 
            "impact": "May affect service confidentiality",
            "severity": "Medium",  
            "affected_versions": "HarmonyOS4.2.0, HarmonyOS2.0.0",
            "is_huawei": True
        },
        AdvisoryData(
            summary="Permission verification vulnerability\nMay affect service confidentiality",
            aliases=["CVE-2024-45449"],
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(type="huawei", name="harmonyos"),
                    affected_version_range=VersionRange.from_string("vers:generic/=4.2.0")
                ),
                AffectedPackage(
                    package=PackageURL(type="huawei", name="harmonyos"),
                    affected_version_range=VersionRange.from_string("vers:generic/=2.0.0") 
                )
            ],
            references=[
                Reference(
                    url="https://nvd.nist.gov/vuln/detail/CVE-2024-45449",
                    reference_id="CVE-2024-45449",
                    severities=[
                        VulnerabilitySeverity(
                            system=GENERIC,
                            value="medium"
                        )
                    ]
                )
            ],
            date_published=None,
            url="https://consumer.huawei.com/en/support/bulletin/2024/9/"
        )
    ),
    (
        {
            "cve_id": "CVE-2024-34740",
            "severity": "High",
            "affected_versions": "HarmonyOS4.2.0, HarmonyOS4.0.0",
            "is_huawei": False  
        },
        AdvisoryData(
            aliases=["CVE-2024-34740"],
            summary="Third-party vulnerability affecting HarmonyOS4.2.0,HarmonyOS4.0.0",
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(type="huawei", name="harmonyos"),
                    affected_version_range=VersionRange.from_string("vers:generic/=4.2.0")
                ),
                AffectedPackage( 
                    package=PackageURL(type="huawei", name="harmonyos"),
                    affected_version_range=VersionRange.from_string("vers:generic/=4.0.0")
                )
            ],
            references=[
                Reference(
                    url="https://nvd.nist.gov/vuln/detail/CVE-2024-34740",
                    reference_id="CVE-2024-34740", 
                    severities=[
                        VulnerabilitySeverity(
                            system=GENERIC,
                            value="high"
                        )
                    ]
                )
            ],
            date_published=None,
            url="https://consumer.huawei.com/en/support/bulletin/2024/9/"
        )
    )
]

@pytest.mark.parametrize(("test_data", "expected"), test_cases)
def test_to_advisory_data_conversion(test_data, expected):
    """Test converting raw data into proper advisorys"""
    from vulnerabilities.pipelines.huawei_bulletin_importer import HuaweiBulletinImporterPipeline
    pipeline = HuaweiBulletinImporterPipeline()
    found = pipeline.to_advisory_data(test_data)
    assert expected.aliases == found.aliases 
    assert expected.summary == found.summary
    exp_pkgs = sorted(expected.affected_packages, key=lambda x: str(x.affected_version_range))
    found_pkgs = sorted(found.affected_packages, key=lambda x: str(x.affected_version_range))
    assert len(exp_pkgs) == len(found_pkgs)
    for exp_pkg, found_pkg in zip(exp_pkgs, found_pkgs):
        assert exp_pkg.package.type == found_pkg.package.type 
        assert exp_pkg.package.name == found_pkg.package.name
        assert str(exp_pkg.affected_version_range) == str(found_pkg.affected_version_range)
    assert len(expected.references) == len(found.references)
    for exp_ref, found_ref in zip(expected.references, found.references):
        assert exp_ref.reference_id == found_ref.reference_id
        assert exp_ref.url == found_ref.url
        assert len(exp_ref.severities) == len(found_ref.severities)

        for exp_sev, found_sev in zip(exp_ref.severities, found_ref.severities):
            assert exp_sev.system == found_sev.system
            assert exp_sev.value == found_sev.value

def test_invalid_data():
    """Make sure we handle bad input properly"""
    from vulnerabilities.pipelines.huawei_bulletin_importer import HuaweiBulletinImporterPipeline

    pipeline = HuaweiBulletinImporterPipeline()
    bad_data = {
        "description": "Test desc",
        "severity": "High", 
        "affected_versions": "HarmonyOS4.2.0"
    }
    assert pipeline.to_advisory_data(bad_data) is None
    bad_data = {
        "cve_id": "CVE-2024-12345", 
        "severity": "High",
        "affected_versions": "" 
    }
    assert pipeline.to_advisory_data(bad_data) is None

def test_extract_version():
    """Check that we parse version strings ok"""
    from vulnerabilities.pipelines.huawei_bulletin_importer import extract_version
    assert extract_version("HarmonyOS4.2.0") == ("harmonyos", "4.2.0")
    assert extract_version("EMUI 14.0.0") == ("emui", "14.0.0") 
    assert extract_version("invalid version") == ("", "invalid version")
