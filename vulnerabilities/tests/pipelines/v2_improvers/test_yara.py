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

from vulnerabilities.models import DetectionRule
from vulnerabilities.pipelines.v2_improvers.yara_rules import YaraRulesImproverPipeline

BASE_DIR = Path(__file__).resolve().parent
TEST_REPO_DIR = (BASE_DIR / "../../test_data/yara").resolve()


@pytest.mark.django_db
def test_collect_and_store_rules_from_test_repo_dir():
    mock_vcs_response = MagicMock()
    mock_vcs_response.dest_dir = str(TEST_REPO_DIR)

    improver = YaraRulesImproverPipeline()
    improver.vcs_responses = [(mock_vcs_response, "https://github.com/mock/repo")]
    improver.collect_and_store_rules()

    assert DetectionRule.objects.exists()
    assert DetectionRule.objects.count() == 4
