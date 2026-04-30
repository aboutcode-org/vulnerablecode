#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from datetime import datetime
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import DetectionRule
from vulnerabilities.pipelines.v2_improvers.detection_rules import DetectionRulesPipeline

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "../../test_data", "detection_rules")


@pytest.mark.django_db
@patch("vulnerabilities.pipelines.v2_improvers.detection_rules.fetch_via_vcs")
def test_detection_rules_improver(mock_fetch_via_vcs):
    mock_vcs_response = Mock()
    mock_vcs_response.dest_dir = TEST_DATA
    mock_fetch_via_vcs.return_value = mock_vcs_response

    adv1 = AdvisoryV2.objects.create(
        advisory_id="VCIO-123-2002",
        datasource_id="ds",
        avid="ds/VCIO-123-2002",
        unique_content_id="i3giu",
        url="https://test.com",
        date_collected=datetime.now(),
    )
    alias = AdvisoryAlias.objects.create(alias="CVE-2007-4387")
    adv1.aliases.add(alias)

    improver = DetectionRulesPipeline()
    improver.execute()
    assert DetectionRule.objects.count() > 0
