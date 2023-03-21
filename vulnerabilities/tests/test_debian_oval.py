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
import xml.etree.ElementTree as ET
from unittest.mock import patch

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importers.debian_oval import DebianOvalImporter
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.improvers.valid_versions import DebianOvalImprover
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


@patch("vulnerabilities.improvers.valid_versions.DebianOvalImprover.get_package_versions")
def test_debian_oval_improver(mock_response):
    advisory_file = os.path.join(TEST_DATA, f"debian-oval-expected.json")
    with open(advisory_file) as exp:
        advisories = [AdvisoryData.from_dict(adv) for adv in (json.load(exp))]
    mock_response.return_value = [
        "1.1.0",
        "1.1.1",
        "1.1.2",
        "1.1.3",
        "1.1.4",
        "1.1.5",
        "1.1.6",
        "1.1.7",
        "1.1.8",
    ]
    improvers = [DebianOvalImprover(), DefaultImprover()]
    result = []
    for improver in improvers:
        for advisory in advisories:
            inference = [data.to_dict() for data in improver.get_inferences(advisory)]
            result.extend(inference)
    expected_file = os.path.join(TEST_DATA, f"debian-oval-improver-expected.json")
    util_tests.check_results_against_json(result, expected_file)
