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

from django.test import TestCase
from packageurl import PackageURL

from vulnerabilities import severity_systems
from vulnerabilities.import_runner import process_advisories
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.importers.postgresql import to_advisories
from vulnerabilities.improve_runner import ImproveRunner
from vulnerabilities.improve_runner import process_inferences
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.tests import util_tests
from vulnerabilities.utils import AffectedPackage

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(
    BASE_DIR,
    "test_data/postgresql",
)


class TestPostgreSQLImporter(TestCase):
    def test_to_advisories(self):
        with open(os.path.join(TEST_DATA, "advisories.html")) as f:
            raw_data = f.read()
        advisories = to_advisories(raw_data)
        result = [data.to_dict() for data in advisories]
        expected_file = os.path.join(TEST_DATA, f"parse-advisory-postgresql-expected.json")
        util_tests.check_results_against_json(result, expected_file)

    def test_run_default_improver(self):
        with open(os.path.join(TEST_DATA, "improver-data.json")) as f:
            raw_data = json.load(f)
        advisories = [AdvisoryData.from_dict(data) for data in raw_data]
        process_advisories(advisories, "postgresql")
        ImproveRunner(DefaultImprover).run()
