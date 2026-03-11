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

from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines.v2_importers import nvd_importer
from vulnerabilities.severity_systems import Cvssv3ScoringSystem
from vulnerabilities.tests.util_tests import VULNERABLECODE_REGEN_TEST_FIXTURES as REGEN

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "nvd_v2"


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
            "id": "CVE-2025-45988",
            "sourceIdentifier": "cve@mitre.org",
            "published": "2025-06-13T12:15:34.403",
            "lastModified": "2025-07-10T12:16:15.107",
            "vulnStatus": "Analyzed",
            "cveTags": [],
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Blink routers BL-WR9000 V2.4.9 , BL-AC2100_AZ3 V1.0.4, BL-X10_AC8 v1.0.5 , BL-LTE300 v1.2.3, BL-F1200_AT1 v1.0.0, BL-X26_AC8 v1.2.8, BLAC450M_AE4 v4.0.0 and BL-X26_DA3 v1.2.7 were discovered to contain multiple command injection vulnerabilities via the cmd parameter in the bs_SetCmd function.",
                },
                {
                    "lang": "es",
                    "value": "Se descubrió que los enrutadores Blink BL-WR9000 V2.4.9, BL-AC2100_AZ3 V1.0.4, BL-X10_AC8 v1.0.5, BL-LTE300 v1.2.3, BL-F1200_AT1 v1.0.0, BL-X26_AC8 v1.2.8, BLAC450M_AE4 v4.0.0 y BL-X26_DA3 v1.2.7 contenían múltiples vulnerabilidades de inyección de comandos a través del parámetro cmd en la función bs_SetCmd.",
                },
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                        "type": "Secondary",
                        "cvssData": {
                            "version": "3.1",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "attackVector": "NETWORK",
                            "attackComplexity": "LOW",
                            "privilegesRequired": "NONE",
                            "userInteraction": "NONE",
                            "scope": "UNCHANGED",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "HIGH",
                            "availabilityImpact": "HIGH",
                        },
                        "exploitabilityScore": 3.9,
                        "impactScore": 5.9,
                    }
                ]
            },
            "weaknesses": [
                {
                    "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                    "type": "Secondary",
                    "description": [{"lang": "en", "value": "CWE-77"}],
                }
            ],
            "configurations": [
                {
                    "operator": "AND",
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:o:b-link:bl-wr9000_firmware:2.4.9:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "0D1A3280-9C15-4961-8C69-9ECE34528FDB",
                                }
                            ],
                        },
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:h:b-link:bl-wr9000:-:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "2D5ADB0D-6D03-448A-A0F3-7C238A20AF46",
                                }
                            ],
                        },
                    ],
                },
                {
                    "operator": "AND",
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:o:b-link:bl-ac1900_firmware:1.0.2:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "BE554304-8F2B-40A1-98CB-DE641B4CCE61",
                                }
                            ],
                        },
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:h:b-link:bl-ac1900:-:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "2C5CA5E8-C497-475E-B0CE-6F54B6E9BFA8",
                                }
                            ],
                        },
                    ],
                },
                {
                    "operator": "AND",
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:o:b-link:bl-ac2100_az3_firmware:1.0.4:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "05E31365-4655-4B8D-9B75-AE70292C12C3",
                                }
                            ],
                        },
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:h:b-link:bl-ac2100_az3:-:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "3B134A86-F380-4BE4-9CEC-5CBAE046CF8B",
                                }
                            ],
                        },
                    ],
                },
                {
                    "operator": "AND",
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:o:b-link:bl-x10_ac8_firmware:1.0.5:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "AAA6D548-72E1-435B-8EDB-50C1C258CE9C",
                                }
                            ],
                        },
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:h:b-link:bl-x10_ac8:-:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "B153FF75-DDAF-4B43-8D54-C8211C607C2C",
                                }
                            ],
                        },
                    ],
                },
                {
                    "operator": "AND",
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:o:b-link:bl-lte300_firmware:1.2.3:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "8907D058-539D-44B8-BC30-EC137B4C6841",
                                }
                            ],
                        },
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:h:b-link:bl-lte300:-:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "4CD2D0EC-F71B-4CD6-8013-EDCDE49B6BC9",
                                }
                            ],
                        },
                    ],
                },
                {
                    "operator": "AND",
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:o:b-link:bl-f1200_at1_firmware:1.0.0:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "3DD8A5B3-0FF1-4512-9AEB-68A801956085",
                                }
                            ],
                        },
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:h:b-link:bl-f1200_at1:-:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "9391FA6B-40EF-4A53-9B38-3F5EA0611970",
                                }
                            ],
                        },
                    ],
                },
                {
                    "operator": "AND",
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:o:b-link:bl-x26_ac8_firmware:1.2.8:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "FCE90D05-D32B-4C52-917C-024FB4814751",
                                }
                            ],
                        },
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:h:b-link:bl-x26_ac8:-:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "A13AD09A-4BF0-49B9-AB05-439D34413C81",
                                }
                            ],
                        },
                    ],
                },
                {
                    "operator": "AND",
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:o:b-link:blac450m_ae4_firmware:4.0.0:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "5422B990-7572-42A1-89C4-D8FEEEC066ED",
                                }
                            ],
                        },
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:h:b-link:blac450m_ae4:-:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "A469F008-B95F-480C-A677-43E6D448FEEB",
                                }
                            ],
                        },
                    ],
                },
                {
                    "operator": "AND",
                    "nodes": [
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:o:b-link:bl-x26_da3_firmware:1.2.7:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "D3D8F5C4-F1A2-4E88-A795-DEAC4E77B3C1",
                                }
                            ],
                        },
                        {
                            "operator": "OR",
                            "negate": False,
                            "cpeMatch": [
                                {
                                    "vulnerable": False,
                                    "criteria": "cpe:2.3:h:b-link:bl-x26_da3:-:*:*:*:*:*:*:*",
                                    "matchCriteriaId": "1C8F576A-7D13-4311-9FDD-9BFB4E5705D8",
                                }
                            ],
                        },
                    ],
                },
            ],
            "references": [
                {
                    "url": "https://github.com/glkfc/IoT-Vulnerability/blob/main/LB-LINK/LB-LINK_cmd%20Indicates%20the%20unauthorized%20command%20injection/The%20LB-LINK_cmd%20command%20is%20used%20to%20inject%20information.md",
                    "source": "cve@mitre.org",
                    "tags": ["Exploit"],
                }
            ],
        }
    }


def test_CveItem_severities():
    expected_severities = [
        VulnerabilitySeverity(
            system=Cvssv3ScoringSystem(
                identifier="cvssv3.1",
                name="CVSSv3.1 Base Score",
                url="https://www.first.org/cvss/v3-1/",
                notes="CVSSv3.1 base score and vector",
            ),
            value="9.8",
            scoring_elements="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            published_at=None,
            url="https://nvd.nist.gov/vuln/detail/CVE-2025-45988",
        ),
    ]

    found_severities = nvd_importer.CveItem(cve_item=get_test_cve_item()).severities
    assert found_severities == expected_severities


def test_CveItem_cpes():
    expected_cpes = [
        "cpe:2.3:o:b-link:bl-wr9000_firmware:2.4.9:*:*:*:*:*:*:*",
        "cpe:2.3:h:b-link:bl-wr9000:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:b-link:bl-ac1900_firmware:1.0.2:*:*:*:*:*:*:*",
        "cpe:2.3:h:b-link:bl-ac1900:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:b-link:bl-ac2100_az3_firmware:1.0.4:*:*:*:*:*:*:*",
        "cpe:2.3:h:b-link:bl-ac2100_az3:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:b-link:bl-x10_ac8_firmware:1.0.5:*:*:*:*:*:*:*",
        "cpe:2.3:h:b-link:bl-x10_ac8:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:b-link:bl-lte300_firmware:1.2.3:*:*:*:*:*:*:*",
        "cpe:2.3:h:b-link:bl-lte300:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:b-link:bl-f1200_at1_firmware:1.0.0:*:*:*:*:*:*:*",
        "cpe:2.3:h:b-link:bl-f1200_at1:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:b-link:bl-x26_ac8_firmware:1.2.8:*:*:*:*:*:*:*",
        "cpe:2.3:h:b-link:bl-x26_ac8:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:b-link:blac450m_ae4_firmware:4.0.0:*:*:*:*:*:*:*",
        "cpe:2.3:h:b-link:blac450m_ae4:-:*:*:*:*:*:*:*",
        "cpe:2.3:o:b-link:bl-x26_da3_firmware:1.2.7:*:*:*:*:*:*:*",
        "cpe:2.3:h:b-link:bl-x26_da3:-:*:*:*:*:*:*:*",
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
        "Blink routers BL-WR9000 V2.4.9 , BL-AC2100_AZ3 V1.0.4, BL-X10_AC8 v1.0.5 , "
        "BL-LTE300 v1.2.3, BL-F1200_AT1 v1.0.0, BL-X26_AC8 v1.2.8, BLAC450M_AE4 "
        "v4.0.0 and BL-X26_DA3 v1.2.7 were discovered to contain multiple command "
        "injection vulnerabilities via the cmd parameter in the bs_SetCmd function."
    )

    assert nvd_importer.CveItem(cve_item=get_test_cve_item()).summary == expected_summary


def test_CveItem_reference_urls():
    expected_urls = [
        "https://github.com/glkfc/IoT-Vulnerability/blob/main/LB-LINK/LB-LINK_cmd%20Indicates%20the%20unauthorized%20command%20injection/The%20LB-LINK_cmd%20command%20is%20used%20to%20inject%20information.md"
    ]

    assert nvd_importer.CveItem(cve_item=get_test_cve_item()).reference_urls == expected_urls
