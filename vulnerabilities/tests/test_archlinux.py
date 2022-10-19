#
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
from unittest.mock import patch

from django.test import TestCase

from vulnerabilities import models
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.importers import archlinux
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/archlinux")


def test_parse_advisory_single():
    record = {
        "name": "AVG-2781",
        "packages": ["python-pyjwt"],
        "status": "Unknown",
        "severity": "Unknown",
        "type": "unknown",
        "affected": "2.3.0-1",
        "fixed": "2.4.0-1",
        "ticket": None,
        "issues": ["CVE-2022-29217"],
        "advisories": [],
    }

    advisory_data = archlinux.ArchlinuxImporter().parse_advisory(record)
    result = [data.to_dict() for data in advisory_data]
    expected_file = os.path.join(TEST_DATA, f"parse-advisory-archlinux-expected.json")
    util_tests.check_results_against_json(result, expected_file)


@patch("vulnerabilities.importers.archlinux.ArchlinuxImporter.fetch")
def test_archlinux_importer(mock_response):
    with open(os.path.join(TEST_DATA, "archlinux-multi.json")) as f:
        mock_response.return_value = json.load(f)

    expected_file = os.path.join(TEST_DATA, f"archlinux-multi-expected.json")
    result = [data.to_dict() for data in list(archlinux.ArchlinuxImporter().advisory_data())]
    util_tests.check_results_against_json(result, expected_file)
