#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from vulnerabilities.pipelines.v2_importers.retiredotnet_importer import (
    RetireDotnetImporterPipeline,
)
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "retiredotnet_v2"


def test_vuln_id_from_desc():
    importer = RetireDotnetImporterPipeline()
    gibberish = "xyzabcpqr123" * 50 + "\n" * 100
    res = importer.vuln_id_from_desc(gibberish)
    assert res is None

    desc = "abcdef CVE-2002-1968 pqrstuvwxyz:_|-|"
    res = importer.vuln_id_from_desc(desc)
    assert res == "CVE-2002-1968"


@pytest.mark.django_db
def test_retiredotnet_advisories_per_file():
    pipeline = RetireDotnetImporterPipeline()
    test_file = TEST_DATA / "12.json"
    expected_file = TEST_DATA / "expected_file.json"
    pipeline.vcs_response = Mock(dest_dir=TEST_DATA)

    with patch.object(Path, "glob", return_value=[test_file]):
        result = [adv.to_dict() for adv in pipeline.collect_advisories()]

    util_tests.check_results_against_json(result, expected_file)
