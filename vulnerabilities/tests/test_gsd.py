#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import datetime
import json
import os
from unittest import TestCase

from vulnerabilities.importer import Reference
from vulnerabilities.importers.gsd import get_aliases
from vulnerabilities.importers.gsd import get_description
from vulnerabilities.importers.gsd import get_published_date_nvd_nist_gov
from vulnerabilities.importers.gsd import get_references
from vulnerabilities.importers.gsd import get_severities
from vulnerabilities.importers.gsd import get_summary
from vulnerabilities.importers.gsd import parse_advisory_data
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/gsd")


class TestGSDImporter(TestCase):
    def test_to_advisories1(self):
        with open(os.path.join(TEST_DATA, "GSD-2016-20005.json")) as f:
            raw_data = json.load(f)
            imported_data = parse_advisory_data(raw_data, "GSD-2016-20005.json")
        expected_file = os.path.join(TEST_DATA, "GSD-2016-20005-expected.json")
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories2(self):
        with open(os.path.join(TEST_DATA, "GSD-2022-4030.json")) as f:
            raw_data = json.load(f)
            imported_data = parse_advisory_data(raw_data, "GSD-2022-4030.json")
        expected_file = os.path.join(TEST_DATA, "GSD-2022-4030-expected.json")
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories3(self):
        with open(os.path.join(TEST_DATA, "GSD-2002-0001.json")) as f:
            raw_data = json.load(f)
            imported_data = parse_advisory_data(raw_data, "GSD-2022-4030.json")
        expected_file = os.path.join(TEST_DATA, "GSD-2002-0001-expected.json")
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories4(self):
        with open(os.path.join(TEST_DATA, "GSD-2006-0326.json")) as f:
            raw_data = json.load(f)
            imported_data = parse_advisory_data(raw_data, "GSD-2022-4030.json")
        expected_file = os.path.join(TEST_DATA, "GSD-2006-0326-expected.json")
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_get_references(self):
        assert get_references(
            {
                "references": {
                    "reference_data": [
                        {
                            "name": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198",
                            "refsource": "CONFIRM",
                            "tags": ["Vendor Advisory"],
                            "url": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198",
                        }
                    ]
                }
            }
        ) == [
            Reference(
                reference_id="",
                url="https://kc.mcafee.com/corporate/index?page=content&id=SB10198",
                severities=[],
            )
        ]

    def test_get_description(self):
        assert get_description(
            {
                "description": {
                    "description_data": [
                        {
                            "lang": "eng",
                            "value": "User Name Disclosure in the server in McAfee Network Data Loss Prevention (NDLP) 9.3.x allows remote attackers to view user information via the appliance web interface.",
                        }
                    ]
                }
            }
        ) == [
            "User Name Disclosure in the server in McAfee Network Data Loss Prevention (NDLP) 9.3.x allows remote attackers to view user information via the appliance web interface."
        ]

    def test_get_aliases_cve_org(self):
        assert get_aliases(
            {
                "CVE_data_meta": {
                    "ASSIGNER": "secure@intel.com",
                    "ID": "CVE-2017-4017",
                    "STATE": "PUBLIC",
                }
            }
        ) == ["CVE-2017-4017"]
        assert get_aliases(
            {
                "CVE_data_meta": {
                    "ASSIGNER": "secure@intel.com",
                    "ID": "CVE-2017-4017",
                    "STATE": "PUBLIC",
                },
                "source": {"advisory": "GHSA-v8x6-59g4-5g3w", "discovery": "UNKNOWN"},
            }
        ) == ["CVE-2017-4017", "GHSA-v8x6-59g4-5g3w"]
        assert get_aliases(
            {"source": {"advisory": "GHSA-v8x6-59g4-5g3w", "discovery": "UNKNOWN"}}
        ) == ["GHSA-v8x6-59g4-5g3w"]

    def test_get_summary(self):
        assert (
            get_summary({"CVE_data_meta": {"TITLE": "DoS vulnerability: Invalid Accent Colors"}})
            == "DoS vulnerability: Invalid Accent Colors"
        )

    def test_get_severities(self):
        assert get_severities(
            {
                "impact": {
                    "cvss": {
                        "attackComplexity": "LOW",
                        "attackVector": "NETWORK",
                        "availabilityImpact": "HIGH",
                        "baseScore": 5.7,
                        "baseSeverity": "MEDIUM",
                        "confidentialityImpact": "NONE",
                        "integrityImpact": "NONE",
                        "privilegesRequired": "LOW",
                        "scope": "UNCHANGED",
                        "userInteraction": "REQUIRED",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H",
                        "version": "3.1",
                    }
                }
            }
        ) == ["CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H"]
        assert get_severities(
            {
                "impact": {
                    "baseMetricV2": {
                        "acInsufInfo": False,
                        "cvssV2": {
                            "accessComplexity": "LOW",
                            "accessVector": "NETWORK",
                            "authentication": "NONE",
                            "availabilityImpact": "PARTIAL",
                            "baseScore": 7.5,
                            "confidentialityImpact": "PARTIAL",
                            "integrityImpact": "PARTIAL",
                            "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                            "version": "2.0",
                        },
                        "exploitabilityScore": 10.0,
                        "impactScore": 6.4,
                        "obtainAllPrivilege": False,
                        "obtainOtherPrivilege": False,
                        "obtainUserPrivilege": False,
                        "severity": "HIGH",
                        "userInteractionRequired": False,
                    },
                    "baseMetricV3": {
                        "cvssV3": {
                            "attackComplexity": "LOW",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "HIGH",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "HIGH",
                            "privilegesRequired": "NONE",
                            "scope": "UNCHANGED",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "version": "3.1",
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 5.9,
                    },
                }
            }
        ) == ["AV:N/AC:L/Au:N/C:P/I:P/A:P", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]

        assert get_severities(
            {
                "impact": {
                    "cvss": [
                        {
                            "baseScore": 8.1,
                            "baseSeverity": "HIGH",
                            "vectorString": "CVSS:3.1/A:H/I:H/C:N/S:U/UI:N/PR:L/AC:L/AV:N",
                            "version": "3.1",
                        }
                    ]
                }
            }
        ) == ["CVSS:3.1/A:H/I:H/C:N/S:U/UI:N/PR:L/AC:L/AV:N"]

        assert get_severities(
            {
                "impact": {
                    "baseMetricV3": {
                        "cvssV3": {
                            "attackComplexity": "LOW",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "HIGH",
                            "baseScore": 8.1,
                            "baseSeverity": "HIGH",
                            "confidentialityImpact": "NONE",
                            "integrityImpact": "HIGH",
                            "privilegesRequired": "LOW",
                            "scope": "UNCHANGED",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H",
                            "version": "3.1",
                        },
                        "exploitabilityScore": 2.8,
                        "impactScore": 5.2,
                    }
                }
            }
        ) == ["CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H"]

    def test_get_published_date_nvd_nist_gov(self):
        assert get_published_date_nvd_nist_gov(
            {"publishedDate": "2022-06-23T07:15Z"}
        ) == datetime.datetime(2022, 6, 23, 7, 15, 0, 0).replace(tzinfo=datetime.timezone.utc)
        assert get_published_date_nvd_nist_gov({}) is None
