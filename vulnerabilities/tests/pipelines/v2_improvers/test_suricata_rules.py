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
from vulnerabilities.pipelines.v2_improvers.suricata_rules import SuricataRulesImproverPipeline

BASE_DIR = Path(__file__).resolve().parent
TEST_REPO_DIR = (BASE_DIR / "../../test_data/suricata").resolve()


@pytest.mark.django_db
def test_collect_and_store_suricata_rules():
    mock_vcs_response = MagicMock()
    mock_vcs_response.dest_dir = str(TEST_REPO_DIR)

    improver = SuricataRulesImproverPipeline()
    improver.pipeline_id = "test-suricata-rules"
    improver.repo_url = "https://github.com/aboutcode-org/repo"
    improver.vcs_response = mock_vcs_response
    improver.collect_and_store_rules()

    assert DetectionRule.objects.exists()
    assert DetectionRule.objects.count() == 2
