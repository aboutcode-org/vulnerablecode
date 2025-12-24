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
from unittest import mock
from unittest.mock import MagicMock

import pytest

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryPOC
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines.v2_improvers.enhance_with_github_poc import (
    GithubPocsImproverPipeline,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TEST_REPO_DIR = os.path.join(BASE_DIR, "../../test_data/github_poc")


@pytest.mark.django_db
@mock.patch("vulnerabilities.pipelines.v2_improvers.enhance_with_github_poc.fetch_via_vcs")
def test_github_poc_db_improver(mock_fetch_via_vcs):
    mock_vcs = MagicMock()
    mock_vcs.dest_dir = TEST_REPO_DIR
    mock_vcs.delete = MagicMock()
    mock_fetch_via_vcs.return_value = mock_vcs

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

    alias1 = AdvisoryAlias.objects.create(alias="CVE-2022-0236")
    alias2 = AdvisoryAlias.objects.create(alias="CVE-2025-0108")
    alias3 = AdvisoryAlias.objects.create(alias="CVE-2025-0309")
    adv1.aliases.add(alias1)
    adv2.aliases.add(alias2)
    adv3.aliases.add(alias3)

    improver = GithubPocsImproverPipeline()
    improver.execute()

    assert len(AdvisoryPOC.objects.all()) == 10
    exploit1 = AdvisoryPOC.objects.get(
        url="https://github.com/iSee857/CVE-2025-0108-PoC",
        is_confirmed=False,
    )
    exploit2 = AdvisoryPOC.objects.get(
        url="https://github.com/FOLKS-iwd/CVE-2025-0108-PoC", advisory=adv2
    )
    exploit3 = AdvisoryPOC.objects.get(
        url="https://github.com/B1ack4sh/Blackash-CVE-2025-0108",
    )
    assert exploit1.url == "https://github.com/iSee857/CVE-2025-0108-PoC"
    assert str(exploit1.created_at) == "2025-02-13 06:39:25+00:00"
    assert str(exploit2.updated_at) == "2025-04-28 07:22:48+00:00"
    assert exploit2.url == "https://github.com/FOLKS-iwd/CVE-2025-0108-PoC"
    assert exploit3.url == "https://github.com/B1ack4sh/Blackash-CVE-2025-0108"
