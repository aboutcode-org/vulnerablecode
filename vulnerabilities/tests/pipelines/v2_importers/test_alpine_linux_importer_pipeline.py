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

import pytest

from vulnerabilities.pipelines.v2_importers.alpine_linux_importer import load_advisories
from vulnerabilities.pipelines.v2_importers.alpine_linux_importer import parse_vuln_ids
from vulnerabilities.pipelines.v2_importers.alpine_linux_importer import process_record
from vulnerabilities.tests import util_tests
from vulnerabilities.tests.pipelines import TestLogger

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "alpine"


def test_alpine_linux_pipeline():
    logger = TestLogger()
    expected_file = TEST_DATA / "expected-advisories-v3.3.json"

    with open(TEST_DATA / "v3.11/main.json") as f:
        found_advisories = list(
            process_record(
                json.loads(f.read()),
                "https://secdb.alpinelinux.org/v3.11/",
                logger=logger.write,
            )
        )
        results = [
            adv.to_dict() for adv in sorted(found_advisories, key=lambda adv: adv.advisory_id)
        ]
        util_tests.check_results_against_json(results, expected_file)

    assert (
        "'4.10-1-r1' is not a valid AlpineVersion InvalidVersion(\"'4.10-1-r1' is not a valid <class 'univers.versions.AlpineLinuxVersion'>\")"
        in logger.getvalue()
    )


def test_process_record_without_packages():
    logger = TestLogger()
    with open(TEST_DATA / TEST_DATA / "v3.3/community.json") as f:
        assert list(process_record(json.loads(f.read()), "", logger=logger.write)) == []
        assert (
            "\"packages\" not found in this record {'apkurl': '{{urlprefix}}/{{distroversion}}/{{reponame}}/{{arch}}/{{pkg.name}}-{{pkg.ver}}.apk', 'archs': ['armhf', 'x86', 'x86_64'], 'reponame': 'community', 'urlprefix': 'https://dl-cdn.alpinelinux.org/alpine', 'distroversion': 'v3.3', 'packages': []}"
            in logger.getvalue()
        )


def test_load_advisories_package_without_name():
    logger = TestLogger()
    package = {
        "secfixes": {"4.10.0-r1": ["XSA-248"], "4.10.0-r2": ["CVE-2018-7540 XSA-252"]},
    }
    list(load_advisories(package, "v3.11", "main", archs=[], url="", logger=logger.write))
    assert (
        "\"name\" is not available in package {'secfixes': {'4.10.0-r1': ['XSA-248'], '4.10.0-r2': ['CVE-2018-7540 XSA-252']}}"
        in logger.getvalue()
    )


def test_load_advisories_package_without_secfixes():
    logger = TestLogger()
    package = {
        "name": "xen",
        "secfixes": {"4.10.0-r1": []},
    }
    list(load_advisories(package, "v3.11", "main", archs=[], url="", logger=logger.write))
    assert "No fixed vulnerabilities in version '4.10.0-r1'" in logger.getvalue()


@pytest.mark.parametrize(
    "test_case",
    [
        # these are the tests are not supported yet
        # when we start supporting these version,
        # they will be moved back to main test suite
        "1.9.5p2-r0",
        "6.6.2p1-r0",
        "6.6.4p1-r1",
        "4.10-1-r1",
    ],
)
def test_load_advisories_package_with_invalid_alpine_version(test_case):
    logger = TestLogger()
    package = {
        "name": "xen",
        "secfixes": {f"{test_case}": ["XSA-248"]},
    }
    result = list(load_advisories(package, "v3.11", "main", archs=[], url="", logger=logger.write))
    assert result != []


@pytest.mark.parametrize(
    "raw_input, expected_vuln_id, expected_aliases",
    [
        ("CVE-2022-42332 XSA-427", "CVE-2022-42332", ["CVE-2022-42332", "XSA-427"]),
        (
            "CVE-2022-42333 CVE-2022-43334 XSA-428",
            "CVE-2022-42333",
            ["CVE-2022-42333", "CVE-2022-43334", "XSA-428"],
        ),
        (
            "CVE-2020-11501 GNUTLS-SA-2020-03-31 CVE-2020-11501",
            "CVE-2020-11501",
            ["CVE-2020-11501", "GNUTLS-SA-2020-03-31", "CVE-2020-11501"],
        ),
        ("CVE_2019-2426", "CVE-2019-2426", ["CVE-2019-2426"]),
        (
            "CVE-2024-22195 GHSA-h5c8-rqwp-cp95",
            "CVE-2024-22195",
            ["CVE-2024-22195", "GHSA-h5c8-rqwp-cp95"],
        ),
        ("CVE-2023-44441 ZDI-CAN-22093", "CVE-2023-44441", ["CVE-2023-44441", "ZDI-CAN-22093"]),
        ("CVE-2022-45059 VSV00010", "CVE-2022-45059", ["CVE-2022-45059", "VSV00010"]),
        ("OSEC-2026-03", "OSEC-2026-03", ["OSEC-2026-03"]),
        ("CVE-2021-35940.patch", "CVE-2021-35940", ["CVE-2021-35940"]),
        ("XSA-207", "XSA-207", ["XSA-207"]),
        ("ALPINE-13661", "ALPINE-13661", ["ALPINE-13661"]),
        ("GHSA-vv2x-vrpj-qqpq", "GHSA-vv2x-vrpj-qqpq", ["GHSA-vv2x-vrpj-qqpq"]),
        ("CVE N/A ZBX-11023", "ZBX-11023", ["ZBX-11023"]),
        ("CVE-2017-2616 (+ regression fix)", "CVE-2017-2616", ["CVE-2017-2616"]),
        (
            "CVE-2020-14342 (Not affected, requires --with-systemd)",
            "CVE-2020-14342",
            ["CVE-2020-14342"],
        ),
        ("CVE-2017-16808 (AoE)", "CVE-2017-16808", ["CVE-2017-16808"]),
        ("CVE-2018-14468 (FrameRelay)", "CVE-2018-14468", ["CVE-2018-14468"]),
        ("CVE-2018-14469 (IKEv1)", "CVE-2018-14469", ["CVE-2018-14469"]),
        ("CVE-2018-14470 (BABEL)", "CVE-2018-14470", ["CVE-2018-14470"]),
        ("CVE-2018-14466 (AFS/RX)", "CVE-2018-14466", ["CVE-2018-14466"]),
        ("CVE-2018-14461 (LDP)", "CVE-2018-14461", ["CVE-2018-14461"]),
        ("CVE-2018-14462 (ICMP)", "CVE-2018-14462", ["CVE-2018-14462"]),
        ("CVE-2018-14465 (RSVP)", "CVE-2018-14465", ["CVE-2018-14465"]),
        ("CVE-2018-14881 (BGP)", "CVE-2018-14881", ["CVE-2018-14881"]),
        ("CVE-2018-14464 (LMP)", "CVE-2018-14464", ["CVE-2018-14464"]),
        ("CVE-2018-14463 (VRRP)", "CVE-2018-14463", ["CVE-2018-14463"]),
        ("CVE-2018-14467 (BGP)", "CVE-2018-14467", ["CVE-2018-14467"]),
        (
            "CVE-2018-10103 (SMB - partially fixed, but SMB printing disabled)",
            "CVE-2018-10103",
            ["CVE-2018-10103"],
        ),
        (
            "CVE-2018-10105 (SMB - too unreliably reproduced, SMB printing disabled)",
            "CVE-2018-10105",
            ["CVE-2018-10105"],
        ),
        ("CVE-2018-14880 (OSPF6)", "CVE-2018-14880", ["CVE-2018-14880"]),
        ("CVE-2018-16451 (SMB)", "CVE-2018-16451", ["CVE-2018-16451"]),
        ("CVE-2018-14882 (RPL)", "CVE-2018-14882", ["CVE-2018-14882"]),
        ("CVE-2018-16227 (802.11)", "CVE-2018-16227", ["CVE-2018-16227"]),
        ("CVE-2018-16229 (DCCP)", "CVE-2018-16229", ["CVE-2018-16229"]),
        ("CVE-2018-16301 (was fixed in libpcap)", "CVE-2018-16301", ["CVE-2018-16301"]),
        ("CVE-2018-16230 (BGP)", "CVE-2018-16230", ["CVE-2018-16230"]),
        ("CVE-2018-16452 (SMB)", "CVE-2018-16452", ["CVE-2018-16452"]),
        ("CVE-2018-16300 (BGP)", "CVE-2018-16300", ["CVE-2018-16300"]),
        ("CVE-2018-16228 (HNCP)", "CVE-2018-16228", ["CVE-2018-16228"]),
        ("CVE-2019-15166 (LMP)", "CVE-2019-15166", ["CVE-2019-15166"]),
        ("CVE-2019-15167 (VRRP)", "CVE-2019-15167", ["CVE-2019-15167"]),
        ("CVE-????-????? TS-2024-005", "TS-2024-005", ["TS-2024-005"]),
        ("CVE-????-????? TS-2024-005", "TS-2024-005", ["TS-2024-005"]),
        ("CVE-2018-14879 (tcpdump -V)", "CVE-2018-14879", ["CVE-2018-14879"]),
        ("CVE-46838", None, []),  # invalid CVE
    ],
)
def test_parse_vuln_ids(raw_input, expected_vuln_id, expected_aliases):
    vuln_id, aliases = parse_vuln_ids(raw_input)
    assert vuln_id == expected_vuln_id
    assert aliases == expected_aliases
