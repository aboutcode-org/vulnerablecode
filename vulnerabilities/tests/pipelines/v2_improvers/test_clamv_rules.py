#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock

import pytest

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryDetectionRule
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines.v2_improvers.clamv_rules import ClamVRulesImproverPipeline

BASE_DIR = Path(__file__).resolve().parent
TEST_REPO_DIR = (BASE_DIR / "../../test_data/clamv").resolve()


@pytest.mark.django_db
@mock.patch("vulnerabilities.pipelines.v2_improvers.clamv_rules.extract_cvd")
@mock.patch("vulnerabilities.pipelines.v2_improvers.clamv_rules.requests.get")
def test_clamv_rules_db_improver(mock_requests_get, mock_extract_cvd):
    mock_resp = MagicMock()
    mock_resp.iter_content.return_value = [b"fake data"]
    mock_resp.raise_for_status.return_value = None
    mock_requests_get.return_value = mock_resp

    mock_extract_cvd.return_value = TEST_REPO_DIR

    adv1 = AdvisoryV2.objects.create(
        advisory_id="VCIO-123-0001",
        datasource_id="ds",
        avid="ds/VCIO-123-0001",
        unique_content_id="sgsdg45",
        url="https://test.com",
        date_collected=datetime.now(),
    )
    adv2 = AdvisoryV2.objects.create(
        advisory_id="VCIO-123-1002",
        datasource_id="ds",
        avid="ds/VCIO-123-1002",
        unique_content_id="6hd4d6f",
        url="https://test.com",
        date_collected=datetime.now(),
    )
    adv3 = AdvisoryV2.objects.create(
        advisory_id="VCIO-123-1003",
        datasource_id="ds",
        avid="ds/VCIO-123-1003",
        unique_content_id="sd6h4sh",
        url="https://test.com",
        date_collected=datetime.now(),
    )

    alias1 = AdvisoryAlias.objects.create(alias="CVE-2019-1199")
    alias2 = AdvisoryAlias.objects.create(alias="CVE-2020-0720")
    alias3 = AdvisoryAlias.objects.create(alias="CVE-2020-0722")

    adv1.aliases.add(alias1)
    adv2.aliases.add(alias2)
    adv3.aliases.add(alias3)

    improver = ClamVRulesImproverPipeline()
    improver.execute()

    assert AdvisoryDetectionRule.objects.count() == 3
    first_rule = AdvisoryDetectionRule.objects.first()
    assert first_rule.rule_type == "clamav"
