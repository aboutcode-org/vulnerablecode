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

from packageurl import PackageURL

from vulnerabilities.importers import redhat
from vulnerabilities.tests import util_tests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "test_data", "redhat")


def test_rpm_to_purl():
    assert redhat.rpm_to_purl("foobar", "redhat") is None
    assert redhat.rpm_to_purl("foo-bar-devel-0:sys76", "redhat") is None
    assert redhat.rpm_to_purl("kernel-0:2.6.32-754.el6", "redhat") == PackageURL(
        type="rpm",
        namespace="redhat",
        name="kernel",
        version="2.6.32-754",
        qualifiers={"arch": "el6"},
    )


@patch("vulnerabilities.importers.redhat.fetch_cves")
@patch("vulnerabilities.importers.redhat.get_data_from_url")
def test_redhat_importer(get_data_from_url, fetcher):
    redhat_importer = redhat.RedhatImporter()
    response_file = os.path.join(TEST_DATA, "redhat-input.json")

    with open(response_file) as f:
        fetcher.return_value = [json.load(f)]
    bugzilla_2075788_response_file = os.path.join(TEST_DATA, "bugzilla-2075788.json")
    bugzilla_2077736_response_file = os.path.join(TEST_DATA, "bugzilla-2077736.json")
    rhsa_1437 = os.path.join(TEST_DATA, "RHSA_openjdk17_update.json")
    rhsa_1439 = os.path.join(TEST_DATA, "RHSA_openjdk11_update.json")
    get_data_from_url.side_effect = [
        json.load(open(bugzilla_2075788_response_file)),
        json.load(open(bugzilla_2077736_response_file)),
        json.load(open(rhsa_1439)),
        json.load(open(rhsa_1437)),
        None,
    ]
    expected_file = os.path.join(TEST_DATA, "redhat-expected.json")
    imported_data = list(redhat_importer.advisory_data())
    result = [data.to_dict() for data in imported_data]
    util_tests.check_results_against_json(result, expected_file)
