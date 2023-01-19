#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os

from vulnerabilities.importers.suse_scores import SUSESeverityScoreImporter
from vulnerabilities.tests import util_tests
from vulnerabilities.utils import load_yaml

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DIR = os.path.join(BASE_DIR, "test_data/suse_scores")


def test_suse_score_import():
    raw_data = load_yaml(os.path.join(TEST_DIR, "suse-cvss-scores.yaml"))
    expected_file = os.path.join(TEST_DIR, "suse-cvss-scores-expected.json")
    advisories = list(SUSESeverityScoreImporter().to_advisory(raw_data))
    expected_advisories = [adv.to_dict() for adv in advisories]
    util_tests.check_results_against_json(expected_advisories, expected_file)
