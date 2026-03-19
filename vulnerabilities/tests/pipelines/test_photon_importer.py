#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path

from vulnerabilities.pipelines.photon_os_importer import normalize_ranges
from vulnerabilities.pipelines.photon_os_importer import parse_photon_advisory
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent / "test_data" / "photon_os"


def test_normalize_ranges_with_dict():
    data = {"type": "ECOSYSTEM", "events": []}
    assert normalize_ranges(data) == [data]


def test_normalize_ranges_with_list():
    data = [{"type": "ECOSYSTEM", "events": []}]
    assert normalize_ranges(data) == data


def test_normalize_ranges_with_none():
    assert normalize_ranges(None) == []


def test_parse_photon_advisory_with_ranges():
    file = TEST_DATA / "photon_sample_with_ranges.json"
    result = parse_photon_advisory(file_path=file)

    assert result.aliases == ["PHSA-2025-3.0-0815"]
    assert len(result.affected_packages) == 1
    assert str(result.affected_packages[0].fixed_version) == "2.64.0-13.ph3"

    reference_ids = [r.reference_id for r in result.references if r.reference_id]
    assert "CVE-2024-52530" in reference_ids


def test_parse_photon_advisory_without_ranges():
    file = TEST_DATA / "photon_sample_without_ranges.json"
    result = parse_photon_advisory(file_path=file)

    assert result.aliases == ["PHSA-2026-5.0-0785"]
    assert result.affected_packages == []


def test_parse_photon_advisory_dict_ranges_deduplication():
    file = TEST_DATA / "photon_sample_dict_ranges.json"
    result = parse_photon_advisory(file_path=file)

    assert result.aliases == ["PHSA-2024-4.0-0685"]
    # 6 input entries → 2 unique packages after deduplication
    assert len(result.affected_packages) == 2
    package_names = {pkg.package.name for pkg in result.affected_packages}
    assert package_names == {"linux", "linux-aws"}


def test_photon_advisory_expected_output():
    file = TEST_DATA / "photon_sample_with_ranges.json"
    result = parse_photon_advisory(file_path=file)
    result_dict = [result.to_dict()]
    expected_file = TEST_DATA / "photon-expected.json"
    util_tests.check_results_against_json(result_dict, expected_file)
