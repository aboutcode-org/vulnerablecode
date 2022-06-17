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

from vulnerabilities.importers.nvd import extract_cpes
from vulnerabilities.importers.nvd import extract_reference_urls
from vulnerabilities.importers.nvd import extract_summary
from vulnerabilities.importers.nvd import related_to_hardware
from vulnerabilities.importers.nvd import to_advisories

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/nvd/nvd_test.json")


def load_test_data():
    with open(TEST_DATA) as f:
        return json.load(f)


def test_nvd_importer_with_hardware(regen=False):
    expected_file = os.path.join(BASE_DIR, "test_data/nvd/nvd-expected.json")

    result = [data.to_dict() for data in list(to_advisories(load_test_data()))]

    if regen:
        with open(expected_file, "w") as f:
            json.dump(result, f, indent=2)
        expected = result
    else:
        with open(expected_file) as f:
            expected = json.load(f)

    assert result == expected


def get_cve_item():

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


def test_extract_cpes():
    expected_cpes = {
        "cpe:2.3:a:csilvers:gperftools:0.1:*:*:*:*:*:*:*",
        "cpe:2.3:a:csilvers:gperftools:0.2:*:*:*:*:*:*:*",
        "cpe:2.3:a:csilvers:gperftools:*:*:*:*:*:*:*:*",
    }

    found_cpes = set()
    found_cpes.update(extract_cpes(get_cve_item()))

    assert found_cpes == expected_cpes


def test_related_to_hardware():
    assert (
        related_to_hardware(
            cpes=[
                "cpe:2.3:a:csilvers:gperftools:0.1:*:*:*:*:*:*:*",
                "cpe:2.3:h:csilvers:gperftools:0.2:*:*:*:*:*:*:*",
                "cpe:2.3:a:csilvers:gperftools:*:*:*:*:*:*:*:*",
            ]
        )
        == True
    )


def test_extract_summary_with_single_summary():
    expected_summary = (
        "Multiple integer overflows in TCMalloc (tcmalloc.cc) in gperftools "
        "before 0.4 make it easier for context-dependent attackers to perform memory-related "
        "attacks such as buffer overflows via a large size value, which causes less memory to "
        "be allocated than expected."
    )
    found_summary = extract_summary(get_cve_item())
    assert found_summary == expected_summary


def test_extract_reference_urls():
    expected_urls = {
        "http://code.google.com/p/gperftools/source/browse/tags/perftools-0.4/ChangeLog",
        "http://kqueue.org/blog/2012/03/05/memory-allocator-security-revisited/",
    }

    found_urls = extract_reference_urls(get_cve_item())

    assert found_urls == expected_urls
