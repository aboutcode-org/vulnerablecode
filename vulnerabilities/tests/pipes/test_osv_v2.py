#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json
import os
from pathlib import Path
from unittest import TestCase

import saneyaml
from univers.version_constraint import VersionConstraint
from univers.version_range import MavenVersionRange
from univers.version_range import PypiVersionRange
from univers.versions import MavenVersion
from univers.versions import PypiVersion

from vulnerabilities.pipes.osv_v2 import get_explicit_affected_range
from vulnerabilities.pipes.osv_v2 import get_version_ranges_constraints
from vulnerabilities.pipes.osv_v2 import parse_advisory_data_v3
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent / "test_data" / "osv_test"


def test_get_version_ranges_constraints():
    assert get_version_ranges_constraints(
        ranges={"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0.21.8"}]},
        raw_id="GHSA-8hxh-r6f7-jf45",
        supported_ecosystem="maven",
    ) == (
        [VersionConstraint(comparator="<", version=MavenVersion(string="0.21.8"))],
        [VersionConstraint(comparator="=", version=MavenVersion(string="0.21.8"))],
        [],
        [],
    )

    assert get_version_ranges_constraints(
        ranges={
            "events": [
                {"introduced": "0"},
                {"fixed": "91f4af7e6af53e1c6bf17ed36cb2161863eddae4"},
                {"fixed": "18eea90ebb24a9c22248f0b7e18646cc6e3e3e0f"},
                {"fixed": "a1991aeac19c3fec1fdd0d184c6760c90c9f9fc9"},
                {"fixed": "31e41eea6c2322689826e6065ceba82551c565aa"},
                {"fixed": "a40285c5a0288669b72f9d991508d4405885bffc"},
            ],
            "repo": "https://fedoraproject.org/wiki/Infrastructure/Fedorahosted-retirement",
            "type": "GIT",
        },
        raw_id="GHSA-8hxh-r6f7-jf45",
        supported_ecosystem="maven",
    ) == (
        [],
        [],
        [],
        [
            "91f4af7e6af53e1c6bf17ed36cb2161863eddae4",
            "18eea90ebb24a9c22248f0b7e18646cc6e3e3e0f",
            "a1991aeac19c3fec1fdd0d184c6760c90c9f9fc9",
            "31e41eea6c2322689826e6065ceba82551c565aa",
            "a40285c5a0288669b72f9d991508d4405885bffc",
        ],
    )

    assert get_version_ranges_constraints(
        ranges={"type": "ECOSYSTEM", "events": []},
        raw_id="GHSA-8hxh-r6f7-jf45",
        supported_ecosystem="maven",
    ) == (
        [],
        [],
        [],
        [],
    )


def test_get_explicit_affected_constraints():
    assert get_explicit_affected_range(
        affected_pkg={
            "versions": [
                "4.10.2",
                "4.12.2",
                "4.4.0.dev1",
                "4.5.0",
                "4.5.2",
                "4.5.4",
                "4.6.2",
                "4.6.3",
                "4.6.4",
                "4.6.5",
                "4.6.7",
                "4.7.0",
                "4.7.1",
                "4.7.2",
                "4.7.4",
                "4.7.5",
                "4.8.0",
                "4.8.0rc1",
                "4.8.1",
                "4.8.2",
                "4.8.3",
                "4.8.5",
                "4.8.6",
                "4.8.7",
                "4.8.9",
                "4.9.12",
            ]
        },
        raw_id="GHSA-8hxh-r6f7-jf45",
        supported_ecosystem="maven",
    ) == MavenVersionRange(
        constraints=(
            VersionConstraint(comparator="=", version=MavenVersion(string="4.4.0.dev1")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.5.0")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.5.2")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.5.4")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.6.2")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.6.3")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.6.4")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.6.5")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.6.7")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.7.0")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.7.1")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.7.2")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.7.4")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.7.5")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.8.0rc1")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.8.0")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.8.1")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.8.2")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.8.3")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.8.5")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.8.6")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.8.7")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.8.9")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.9.12")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.10.2")),
            VersionConstraint(comparator="=", version=MavenVersion(string="4.12.2")),
        )
    )

    # Invalid versions are skipped.
    assert get_explicit_affected_range(
        affected_pkg={"versions": ["qwqw4684", "4.10.2", "fhgj5449"]},
        raw_id="GHSA-8hxh-r6f7-jf45",
        supported_ecosystem="pypi",
    ) == PypiVersionRange(
        constraints=(VersionConstraint(comparator="=", version=PypiVersion(string="4.10.2")),)
    )


class TestOSVImporter(TestCase):
    def test_to_advisories_github1(self):
        with open(os.path.join(TEST_DATA, "github/github-1.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "github/github-expected-1.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "maven", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_github2(self):
        with open(os.path.join(TEST_DATA, "github/github-2.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "github/github-expected-2.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "composer", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_github3(self):
        with open(os.path.join(TEST_DATA, "github/github-3.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "github/github-expected-3.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "maven", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_github4(self):
        with open(os.path.join(TEST_DATA, "github/github-4.json")) as f:
            mock_response = json.load(f)
        expected_file = os.path.join(TEST_DATA, "github/github-expected-4.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "cargo", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_oss_fuzz1(self):
        with open(os.path.join(TEST_DATA, "oss-fuzz/oss-fuzz-1.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "oss-fuzz/oss-fuzz-expected-1.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "generic", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_oss_fuzz2(self):
        with open(os.path.join(TEST_DATA, "oss-fuzz/oss-fuzz-2.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "oss-fuzz/oss-fuzz-expected-2.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "generic", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_oss_fuzz3(self):
        with open(os.path.join(TEST_DATA, "oss-fuzz/oss-fuzz-3.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "oss-fuzz/oss-fuzz-expected-3.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "generic", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_pypa1(self):
        with open(os.path.join(TEST_DATA, "pypa/pypa-1.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "pypa/pypa-expected-1.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "pypi", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_pypa2(self):
        with open(os.path.join(TEST_DATA, "pypa/pypa-2.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "pypa/pypa-expected-2.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "pypi", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_pypa3(self):
        with open(os.path.join(TEST_DATA, "pypa/pypa-3.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "pypa/pypa-expected-3.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "pypi", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_pypa4(self):
        with open(os.path.join(TEST_DATA, "pypa/pypa-4.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "pypa/pypa-expected-4.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "pypi", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_pypa5(self):
        with open(os.path.join(TEST_DATA, "pypa/pypa-5.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "pypa/pypa-expected-5.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "pypi", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_pypa6(self):
        with open(os.path.join(TEST_DATA, "pypa/pypa-6.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "pypa/pypa-expected-6.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "pypi", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)

    def test_to_advisories_pypa7(self):
        with open(os.path.join(TEST_DATA, "pypa/pypa-7.yaml")) as f:
            mock_response = saneyaml.load(f)
        expected_file = os.path.join(TEST_DATA, "pypa/pypa-expected-7.json")
        imported_data = parse_advisory_data_v3(
            mock_response, "pypi", advisory_url="https://test.com", advisory_text=""
        )
        result = imported_data.to_dict()
        util_tests.check_results_against_json(result, expected_file)
