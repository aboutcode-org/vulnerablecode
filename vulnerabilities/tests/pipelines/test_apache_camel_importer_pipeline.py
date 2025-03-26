#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from bs4 import BeautifulSoup
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import GENERIC
from vulnerabilities.severity_systems import ScoringSystem
from vulnerabilities.tests import util_tests

TEST_DATA = (
    Path(__file__).parent.parent / "test_data" / "apache_camel" / "apache_camel_expected.json"
)
TEST_HTML = Path(__file__).parent.parent / "test_data" / "apache_camel" / "apache_camel_test.html"


def load_test_data(file):
    with open(file) as f:
        return json.load(f)


def test_to_advisory_data():
    """test for parsing the html data"""
    with open(TEST_HTML) as f:
        mock_response = BeautifulSoup(f.read(), features="html.parser")

    expected = load_test_data(TEST_DATA)

    with patch("requests.get") as mock_response_get:
        mock_response_get.return_value.text = mock_response
        from vulnerabilities.pipelines.apache_camel_importer import ApacheCamelImporterPipeline

        pipeline = ApacheCamelImporterPipeline()
        pipeline.raw_data = mock_response
        results = [data.to_dict() for data in pipeline.collect_advisories()]  # advisories

        for result, exp in zip(
            sorted(results, key=lambda x: x["aliases"][0]),
            sorted(expected, key=lambda x: x["aliases"][0]),
        ):
            assert result["aliases"] == exp["aliases"]
            assert result["summary"] == exp["summary"]
            assert len(result["affected_packages"]) == len(exp["affected_packages"])
            for r_pkg, e_pkg in zip(
                sorted(result["affected_packages"], key=lambda x: x["affected_version_range"]),
                sorted(exp["affected_packages"], key=lambda x: x["affected_version_range"]),
            ):
                assert r_pkg["package"]["name"] == e_pkg["package"]["name"]
                assert r_pkg["package"]["type"] == e_pkg["package"]["type"]
