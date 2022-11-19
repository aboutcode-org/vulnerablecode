#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
import xml.etree.ElementTree as ET

from vulnerabilities.importers.debian_oval import DebianOvalImporter
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data/")


def test_debian_oval_importer():
    importer = DebianOvalImporter()
    advsiories = importer.get_data_from_xml_doc(
        ET.parse(os.path.join(TEST_DATA, "debian_oval_data.xml")),
        {"type": "deb", "namespace": "debian", "qualifiers": {"distro": "wheezy"}},
    )
    expected_file = os.path.join(TEST_DATA, f"debian-oval-expected.json")
    util_tests.check_results_against_json(
        [advisory.to_dict() for advisory in advsiories], expected_file
    )
