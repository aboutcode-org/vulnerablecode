#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os

from vulnerabilities.importers.mozilla import to_advisories
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/mozilla/")


def test_import_md():
    md_file = os.path.join(TEST_DATA, "mfsa2006-02.md")
    expected_file_md = os.path.join(TEST_DATA, "expected-md.json")
    advisories_from_md = [adv.to_dict() for adv in to_advisories(md_file)]
    util_tests.check_results_against_json(advisories_from_md, expected_file_md)


def test_import_yml():
    yml_file = os.path.join(TEST_DATA, "mfsa2022-01.yml")
    expected_file_yml = os.path.join(TEST_DATA, "expected-yml.json")
    advisories_from_yml = [adv.to_dict() for adv in to_advisories(yml_file)]
    util_tests.check_results_against_json(advisories_from_yml, expected_file_yml)
