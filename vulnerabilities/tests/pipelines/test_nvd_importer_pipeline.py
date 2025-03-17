#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from pathlib import Path

from vulnerabilities.pipelines import nvd_importer
from vulnerabilities.tests.util_tests import VULNERABLECODE_REGEN_TEST_FIXTURES as REGEN

TEST_DATA = Path(__file__).parent.parent / "test_data" / "nvd"


def load_test_data(file):
    with open(file) as f:
        return json.load(f)


def sorted_advisory_data(advisory_data):
    """
    Return ``advisory_data`` of AdvisoryData mappings where each mapping nested
    list is sorted for stable testing results.
    """
    sorter = lambda dct: tuple(dct.items())
    for data in advisory_data:
        data["aliases"] = sorted(data["aliases"])
        data["affected_packages"] = sorted(data["affected_packages"], key=sorter)
        data["references"] = sorted(data["references"], key=sorter)
    return advisory_data


def test_to_advisories_skips_hardware(regen=REGEN):
    expected_file = TEST_DATA / "nvd-expected.json"

    test_file = TEST_DATA / "nvd_test.json"
    test_data = load_test_data(file=test_file)
    result = [data.to_dict() for data in nvd_importer.to_advisories(test_data)]
    result = sorted_advisory_data(result)

    if regen:
        with open(expected_file, "w") as f:
            json.dump(result, f, indent=2)
        expected = result
    else:
        with open(expected_file) as f:
            expected = json.load(f)
    expected = sorted_advisory_data(expected)

    assert result == expected


def test_to_advisories_marks_rejected_cve(regen=REGEN):
    expected_file = TEST_DATA / "nvd-rejected-expected.json"

    test_file = TEST_DATA / "rejected_nvd.json"
    test_data = load_test_data(file=test_file)
    result = [data.to_dict() for data in nvd_importer.to_advisories(test_data)]
    result = sorted_advisory_data(result)

    if regen:
        with open(expected_file, "w") as f:
            json.dump(result, f, indent=2)
        expected = result
    else:
        with open(expected_file) as f:
            expected = json.load(f)
    expected = sorted_advisory_data(expected)

    assert result == expected


# TODO: use a JSON fixtures instead
def get_test_cve_item():

    return {
        "cve": {
            "data_type": "CVE",
            "data_format": "MITRE",
            "data_version": "4.0",
            "CVE_data_meta": {"ID": "CVE-2005-4895", "ASSIGNER": "cve@mitre.org"},
            "problemtype": {
                "problemtype_data": [{"description": [{"lang": "en", "value": "CWE-189"}]}]
            },
            "references": {
                "reference_data": [
                    {
                        "url": "http://code.google.com/p/gperftools/source/browse/tags/perftools-0.4/ChangeLog",
                        "name": "http://code.google.com/p/gperftools/source/browse/tags/perftools-0.4/ChangeLog",
                        "refsource": "CONFIRM",
                        "tags": [],
                    },
                    {
                        "url": "http://kqueue.org/blog/2012/03/05/memory-allocator-security-revisited/",
                        "name": "http://kqueue.org/blog/2012/03/05/memory-allocator-security-revisited/",
                        "refsource": "MISC",
                        "tags": [],
                    },
                ]
            },
            "description": {
                "description_data": [
                    {
                        "lang": "en",
                        "value": "Multiple integer overflows in TCMalloc (tcmalloc.cc) in gperftools before 0.4 make it easier for context-dependent attackers to perform memory-related attacks such as buffer overflows via a large size value, which causes less memory to be allocated than expected.",
                    }
                ]
            },
        },
        "configurations": {
            "CVE_data_version": "4.0",
            "nodes": [
                {
                    "operator": "OR",
                    "cpe_match": [
                        {
                            "vulnerable": True,
                            "cpe23Uri": "cpe:2.3:a:csilvers:gperftools:0.1:*:*:*:*:*:*:*",
                        },
                        {
                            "vulnerable": True,
                            "cpe23Uri": "cpe:2.3:a:csilvers:gperftools:0.2:*:*:*:*:*:*:*",
                        },
                        {
                            "vulnerable": True,
                            "cpe23Uri": "cpe:2.3:a:csilvers:gperftools:*:*:*:*:*:*:*:*",
                            "versionEndIncluding": "0.3",
                        },
                    ],
                }
            ],
        },
        "impact": {
            "baseMetricV2": {
                "cvssV2": {
                    "version": "2.0",
                    "vectorString": "AV:N/AC:L/Au:N/C:N/I:N/A:P",
                    "accessVector": "NETWORK",
                    "accessComplexity": "LOW",
                    "authentication": "NONE",
                    "confidentialityImpact": "NONE",
                    "integrityImpact": "NONE",
                    "availabilityImpact": "PARTIAL",
                    "baseScore": 5.0,
                },
                "severity": "MEDIUM",
                "exploitabilityScore": 10.0,
                "impactScore": 2.9,
                "obtainAllPrivilege": False,
                "obtainUserPrivilege": False,
                "obtainOtherPrivilege": False,
                "userInteractionRequired": False,
            }
        },
        "publishedDate": "2012-07-25T19:55Z",
        "lastModifiedDate": "2012-08-09T04:00Z",
    }


def test_CveItem_cpes():
    expected_cpes = [
        "cpe:2.3:a:csilvers:gperftools:0.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:csilvers:gperftools:0.2:*:*:*:*:*:*:*",
        "cpe:2.3:a:csilvers:gperftools:*:*:*:*:*:*:*:*",
    ]

    found_cpes = nvd_importer.CveItem(cve_item=get_test_cve_item()).cpes
    assert found_cpes == expected_cpes


def test_is_related_to_hardware():
    assert nvd_importer.is_related_to_hardware("cpe:2.3:h:csilvers:gperftools:0.2:*:*:*:*:*:*:*")
    assert not nvd_importer.is_related_to_hardware(
        "cpe:2.3:a:csilvers:gperftools:0.1:*:*:*:*:*:*:*"
    )
    assert not nvd_importer.is_related_to_hardware("cpe:2.3:a:csilvers:gperftools:*:*:*:*:*:*:*:*")


def test_CveItem_summary_with_single_summary():
    expected_summary = (
        "Multiple integer overflows in TCMalloc (tcmalloc.cc) in gperftools "
        "before 0.4 make it easier for context-dependent attackers to perform memory-related "
        "attacks such as buffer overflows via a large size value, which causes less memory to "
        "be allocated than expected."
    )

    assert nvd_importer.CveItem(cve_item=get_test_cve_item()).summary == expected_summary


def test_CveItem_reference_urls():
    expected_urls = [
        "http://code.google.com/p/gperftools/source/browse/tags/perftools-0.4/ChangeLog",
        "http://kqueue.org/blog/2012/03/05/memory-allocator-security-revisited/",
    ]

    assert nvd_importer.CveItem(cve_item=get_test_cve_item()).reference_urls == expected_urls
