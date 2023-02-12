#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path
from unittest.mock import patch

import pytest
from commoncode import testcase

from vulnerabilities import models
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.improve_runner import ImproveRunner
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.tests import util_tests
from vulnerabilities.tests.example_importer_improver import ExampleAliasImprover
from vulnerabilities.tests.example_importer_improver import ExampleImporter
from vulnerabilities.tests.example_importer_improver import parse_advisory_data


def mock_fetch_advisory_data():
    return [
        {
            "id": "CVE-2021-12341337",
            "summary": "Dummy advisory",
            "advisory_severity": "high",
            "vulnerable": "0.6.18-1.20.0",
            "fixed": "1.20.1",
            "reference": "http://example.com/cve-2021-1234",
            "published_on": "06-10-2021 UTC",
        }
    ]


def mock_fetch_additional_aliases(alias):
    alias_map = {
        "CVE-2021-12341337": ["ANONSEC-1337", "CERTDES-1337"],
    }
    return alias_map.get(alias)


@patch(
    "vulnerabilities.tests.example_importer_improver.fetch_advisory_data", mock_fetch_advisory_data
)
@patch(
    "vulnerabilities.tests.example_importer_improver.fetch_additional_aliases",
    mock_fetch_additional_aliases,
)
class TestExampleImporter(testcase.FileBasedTesting):
    test_data_dir = str(Path(__file__).resolve().parent / "test_data" / "example")

    def test_parse_advisory_data(self):
        raw_data = {
            "id": "CVE-2021-12341337",
            "summary": "Dummy advisory",
            "advisory_severity": "high",
            "vulnerable": "0.6.18-1.20.0",
            "fixed": "1.20.1",
            "reference": "http://example.com/cve-2021-1234",
            "published_on": "06-10-2021 UTC",
        }
        expected_file = self.get_test_loc("parse_advisory_data-expected.json", must_exist=False)
        result = parse_advisory_data(raw_data).to_dict()
        util_tests.check_results_against_json(result, expected_file)

    @pytest.mark.django_db(transaction=True)
    def test_import_framework_using_example_importer(self):
        ImportRunner(ExampleImporter).run()

        for expected in mock_fetch_advisory_data():
            assert models.Advisory.objects.get(aliases__contains=expected["id"])

    @pytest.mark.django_db(transaction=True)
    def test_improve_framework_using_example_improver(self):
        ImportRunner(ExampleImporter).run()
        ImproveRunner(DefaultImprover).run()
        ImproveRunner(ExampleAliasImprover).run()

        assert models.Package.objects.count() == 3
        assert models.PackageRelatedVulnerability.objects.filter(fix=True).count() == 1
        assert models.PackageRelatedVulnerability.objects.filter(fix=False).count() == 2
        assert models.VulnerabilitySeverity.objects.count() == 1
        assert models.VulnerabilityReference.objects.count() == 1

        for expected in mock_fetch_advisory_data():
            assert models.Vulnerability.objects.get(summary=expected["summary"])
