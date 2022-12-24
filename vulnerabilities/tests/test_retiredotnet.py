#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import os

from vulnerabilities.importers.retiredotnet import RetireDotnetImporter
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def test_vuln_id_from_desc():
    importer = RetireDotnetImporter()
    gibberish = "xyzabcpqr123" * 50 + "\n" * 100
    res = importer.vuln_id_from_desc(gibberish)
    assert res is None

    desc = "abcdef CVE-2002-1968 pqrstuvwxyz:_|-|"
    res = importer.vuln_id_from_desc(desc)
    assert res == "CVE-2002-1968"


def test_process_file():
    path = os.path.join(BASE_DIR, "test_data/retiredotnet/test_file.json")
    importer = RetireDotnetImporter()
    expected_file = os.path.join(BASE_DIR, "test_data/retiredotnet/expected_file.json")
    advisory = importer.process_file(path)
    util_tests.check_results_against_json(advisory.to_dict(), expected_file)
