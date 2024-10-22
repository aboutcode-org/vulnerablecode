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
from unittest.mock import patch

import pytest
from packageurl import PackageURL
from univers.version_range import GemVersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importers.ruby import get_affected_packages
from vulnerabilities.importers.ruby import parse_ruby_advisory
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.improvers.valid_versions import RubyImprover
from vulnerabilities.tests import util_tests
from vulnerabilities.tests.util_tests import check_results_against_json
from vulnerabilities.utils import load_yaml

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "ruby")


@pytest.mark.parametrize(
    "filename,expected_filename,schema_type",
    [
        ("CVE-2018-7212.yml", "CVE-2018-7212-expected.json", "gems"),
        ("CVE-2018-11627.yml", "CVE-2018-11627-expected.json", "gems"),
        ("CVE-2007-5770.yml", "CVE-2007-5770-expected.json", "rubies"),
        ("CVE-2010-1330.yml", "CVE-2010-1330-expected.json", "rubies"),
    ],
)
def test_advisories(filename, expected_filename, schema_type):
    file_path = os.path.join(TEST_DATA, filename)
    mock_response = load_yaml(file_path)
    results = parse_ruby_advisory(
        mock_response, schema_type, "https://github.com/rubysec/ruby-advisory-db"
    ).to_dict()
    expected_file = os.path.join(TEST_DATA, expected_filename)
    check_results_against_json(results=results, expected_file=expected_file)


@patch("vulnerabilities.improvers.valid_versions.RubyImprover.get_package_versions")
def test_ruby_improver(mock_response):
    advisory_file = os.path.join(TEST_DATA, f"parse-advisory-ruby-expected.json")
    with open(advisory_file) as exp:
        advisories = [AdvisoryData.from_dict(adv) for adv in (json.load(exp))]
    mock_response.return_value = ["0.2.6", "1.2.7", "1.3.6", "2.2.1", "3.0.2", "3.0.5"]
    improvers = [RubyImprover(), DefaultImprover()]
    result = []
    for improver in improvers:
        for advisory in advisories:
            inference = [data.to_dict() for data in improver.get_inferences(advisory)]
            result.extend(inference)
    expected_file = os.path.join(TEST_DATA, f"ruby-improver-expected.json")
    util_tests.check_results_against_json(result, expected_file)


@pytest.mark.parametrize(
    "record,purl,result",
    [
        (
            {"patched_versions": [">= 1.6.5.1"]},
            PackageURL(type="gem", name="jruby"),
            [
                AffectedPackage(
                    package=PackageURL(type="gem", name="jruby"),
                    affected_version_range=GemVersionRange.from_string("vers:gem/<1.6.5.1"),
                )
            ],
        ),
        (
            {"patched_versions": [">= 1.1.3"], "unaffected_versions": ["< 0.1.33"]},
            PackageURL(type="gem", name="'devise_token_auth'"),
            [
                AffectedPackage(
                    package=PackageURL(type="gem", name="'devise_token_auth'"),
                    affected_version_range=GemVersionRange.from_string("vers:gem/<1.1.3"),
                ),
                AffectedPackage(
                    package=PackageURL(type="gem", name="'devise_token_auth'"),
                    affected_version_range=GemVersionRange.from_string("vers:gem/>=0.1.33"),
                ),
            ],
        ),
    ],
)
def test_get_affected_packages(record, purl, result):
    assert get_affected_packages(record, purl) == result
