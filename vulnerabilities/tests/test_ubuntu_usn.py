#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import bz2
import json
import os
from collections import OrderedDict
from unittest import TestCase
from unittest.mock import MagicMock
from unittest.mock import patch

from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.importers.ubuntu_usn import UbuntuUSNImporter
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DIR = os.path.join(BASE_DIR, "test_data", "ubuntu_usn_db")


def test_ubuntu_usn():
    database = os.path.join(TEST_DIR, "database-all.json.bz2")
    with open(database, "rb") as f:
        raw_data = f.read()
        db = json.loads(bz2.decompress(raw_data))
        advisories = UbuntuUSNImporter().to_advisories(db)
        expected_file = os.path.join(TEST_DIR, f"ubuntu-usn-expected.json")
        result = [data.to_dict() for data in list(advisories)]
        util_tests.check_results_against_json(result, expected_file)
