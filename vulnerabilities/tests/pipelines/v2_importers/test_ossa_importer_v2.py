#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from vulnerabilities.pipelines.v2_importers.ossa_importer_v2 import OSSAImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "ossa"


@pytest.fixture
def mock_vcs_response():
    mock = MagicMock()
    mock.dest_dir = str(TEST_DATA)
    mock.delete = MagicMock()
    return mock


@pytest.fixture
def mock_fetch_via_vcs(mock_vcs_response):
    with patch("vulnerabilities.pipelines.v2_importers.ossa_importer_v2.fetch_via_vcs") as mock:
        mock.return_value = mock_vcs_response
        yield mock


def test_collect_advisories(mock_fetch_via_vcs):
    pipeline = OSSAImporterPipeline()
    pipeline.clone()
    advisories = [adv.to_dict() for adv in pipeline.collect_advisories()]
    expected_file = TEST_DATA / "expected.json"
    util_tests.check_results_against_json(advisories, expected_file)
