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
