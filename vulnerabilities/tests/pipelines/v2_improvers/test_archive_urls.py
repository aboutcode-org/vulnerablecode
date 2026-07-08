# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import MagicMock

import pytest

from vulnerabilities.models import AdvisoryReference
from vulnerabilities.pipelines.v2_improvers.archive_urls import ArchiveImproverPipeline


@pytest.mark.django_db
def test_archive_urls_pipeline(monkeypatch):
    advisory = AdvisoryReference.objects.create(url="https://example.com", archive_url=None)

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.url = "https://web.archive.org/web/20250519082420/https://example.com"

    monkeypatch.setattr(
        f"vulnerabilities.pipelines.v2_improvers.archive_urls.time.sleep", MagicMock()
    )
    monkeypatch.setattr(
        f"vulnerabilities.pipelines.v2_improvers.archive_urls.requests.get",
        MagicMock(return_value=mock_response),
    )

    pipeline = ArchiveImproverPipeline()
    pipeline.archive_urls()

    advisory.refresh_from_db()
    assert advisory.archive_url == "https://web.archive.org/web/20250519082420/https://example.com"
