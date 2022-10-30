#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os

from vulnerabilities.importers import nvd

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/nvd/nvd_test.json")


def load_test_data():
    with open(TEST_DATA) as f:
        return json.load(f)


def sorted_advisory_data(advisory_data):
    """
    Sorted nested lists in a list of AdvisoryData mappings.
    """
    sorter = lambda dct: tuple(dct.items())
    for data in advisory_data:
        data["aliases"] = sorted(data["aliases"])
        data["affected_packages"] = sorted(data["affected_packages"], key=sorter)
        data["references"] = sorted(data["references"], key=sorter)
    return advisory_data


def test_to_advisories_skips_hardware(regen=False):
    expected_file = os.path.join(BASE_DIR, "test_data/nvd/nvd-expected.json")

    test_data = load_test_data()
    result = [data.to_dict() for data in nvd.to_advisories(test_data)]
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

    found_cpes = nvd.CveItem(cve_item=get_test_cve_item()).cpes
    assert found_cpes == expected_cpes


def test_is_related_to_hardware():
    assert nvd.is_related_to_hardware("cpe:2.3:h:csilvers:gperftools:0.2:*:*:*:*:*:*:*")
    assert not nvd.is_related_to_hardware("cpe:2.3:a:csilvers:gperftools:0.1:*:*:*:*:*:*:*")
    assert not nvd.is_related_to_hardware("cpe:2.3:a:csilvers:gperftools:*:*:*:*:*:*:*:*")


def test_CveItem_summary_with_single_summary():
    expected_summary = (
        "Multiple integer overflows in TCMalloc (tcmalloc.cc) in gperftools "
        "before 0.4 make it easier for context-dependent attackers to perform memory-related "
        "attacks such as buffer overflows via a large size value, which causes less memory to "
        "be allocated than expected."
    )

    assert nvd.CveItem(cve_item=get_test_cve_item()).summary == expected_summary


def test_CveItem_reference_urls():
    expected_urls = [
        "http://code.google.com/p/gperftools/source/browse/tags/perftools-0.4/ChangeLog",
        "http://kqueue.org/blog/2012/03/05/memory-allocator-security-revisited/",
    ]

    assert nvd.CveItem(cve_item=get_test_cve_item()).reference_urls == expected_urls
