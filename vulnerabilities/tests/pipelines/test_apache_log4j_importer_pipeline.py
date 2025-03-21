#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from pathlib import Path

from cyclonedx.model.bom import Bom
from defusedxml import ElementTree as SafeElementTree

from vulnerabilities.pipelines.apache_log4j_importer import ApacheLog4jImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent / "test_data" / "apache_log4j"


def test_to_advisories():
    with open(os.path.join(TEST_DATA, "log4j.xml")) as f:
        raw_data = f.read()

    importer = ApacheLog4jImporterPipeline()
    cleaned_data = importer._clean_xml_data(raw_data)
    bom = Bom.from_xml(SafeElementTree.fromstring(cleaned_data))
    advisories = []
    for vulnerability in bom.vulnerabilities:
        advisories.extend(importer._process_vulnerability(vulnerability))

    result = [data.to_dict() for data in advisories]

    expected_file = os.path.join(TEST_DATA, "parse-advisory-apache-log4j-expected.json")
    util_tests.check_results_against_json(result, expected_file)
