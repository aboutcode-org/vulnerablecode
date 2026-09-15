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

import pytest

from vulnerabilities.pipelines.v2_importers.epss_history_importer_v2 import (
    EPSSImporterHistoryPipeline,
)
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "epss_history"

TEST_CVE_FILES = [
    TEST_DATA / "2026/epss_scores-2026-01-01.csv.gz",
    TEST_DATA / "2025/epss_scores-2025-12-01.csv.gz",
]


@pytest.mark.django_db
def test_epss_advisories_history_pipeline():
    pipeline = EPSSImporterHistoryPipeline()
    pipeline.vcs_response = MagicMock()
    pipeline.vcs_response.dest_dir = str(TEST_DATA)
    results = list(pipeline.collect_advisories())

    result_dicts = [adv.to_dict() for adv in results]
    expected_file = Path(TEST_DATA / "epss-expected.json")
    util_tests.check_results_against_json(result_dicts, expected_file)
