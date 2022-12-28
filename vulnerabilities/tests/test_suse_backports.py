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

import saneyaml

from vulnerabilities.importers.debian import DebianBasicImprover
from vulnerabilities.importers.suse_backports import SUSEBackportsImporter
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "suse_backports")


def test_suse_backport_importer():
    input_file = os.path.join(TEST_DATA, "backports-sle11-sp0.yaml")
    expected_file = os.path.join(TEST_DATA, "backports-sle11-sp0-expected.json")
    with open(input_file) as f:
        advisories = SUSEBackportsImporter().process_file(saneyaml.load(f))
        result = [data.to_dict() for data in list(advisories)]
        util_tests.check_results_against_json(result, expected_file)
