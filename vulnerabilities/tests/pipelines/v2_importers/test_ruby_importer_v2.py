#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from vulnerabilities.pipelines.v2_importers.ruby_importer import RubyImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "ruby-v2"

TEST_CVE_FILES = [
    TEST_DATA / "gems/CVE-2020-5257.yml",
    TEST_DATA / "gems/CVE-2024-6531.yml",
    TEST_DATA / "rubies/CVE-2011-2686.yml",
    TEST_DATA / "rubies/CVE-2022-25857.yml",
]


@pytest.mark.django_db
@pytest.mark.parametrize("yml_file", TEST_CVE_FILES)
def test_ruby_advisories_per_file(yml_file):
    pipeline = RubyImporterPipeline()
    pipeline.vcs_response = Mock(dest_dir=TEST_DATA)

    with patch.object(Path, "rglob", return_value=[yml_file]):
        result = [adv.to_dict() for adv in pipeline.collect_advisories()]

    expected_file = yml_file.with_name(yml_file.stem + "-expected.json")
    util_tests.check_results_against_json(result, expected_file)


from vulnerabilities.pipelines.v2_importers.ruby_importer import get_aliases


def test_get_aliases_drops_osvdb_alias():
    record = {
        "cve": "2020-0001",
        "ghsa": "xxxx-yyyy-zzzz",
        "osvdb": 12345,
    }
    aliases = get_aliases(record)
    assert aliases == ["CVE-2020-0001", "GHSA-xxxx-yyyy-zzzz"]
    assert "OSV-12345" not in aliases


def test_get_aliases_only_osvdb():
    record = {
        "osvdb": 65123,
    }
    assert get_aliases(record) == []


def test_get_aliases_no_osvdb():
    record = {
        "cve": "2021-1234",
    }
    assert get_aliases(record) == ["CVE-2021-1234"]


def test_get_aliases_osvdb_and_ghsa_only():
    record = {
        "ghsa": "xxxx-yyyy-zzzz",
        "osvdb": 12345,
    }
    assert get_aliases(record) == ["GHSA-xxxx-yyyy-zzzz"]
