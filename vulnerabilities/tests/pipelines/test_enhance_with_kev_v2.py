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
from unittest.mock import Mock

import pytest

from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryExploit
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines.v2_improvers.enhance_with_kev import VulnerabilityKevPipeline
from vulnerabilities.utils import load_json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEST_DATA = os.path.join(BASE_DIR, "../test_data", "kev_data.json")


@pytest.mark.django_db
@mock.patch("requests.get")
def test_kev_improver(mock_get):
    mock_response = Mock(status_code=200)
    mock_response.json.return_value = load_json(TEST_DATA)
    mock_get.return_value = mock_response

    improver = VulnerabilityKevPipeline()

    # Run the improver when there is no matching aliases
    improver.execute()

    assert AdvisoryExploit.objects.count() == 0

    adv1 = AdvisoryV2.objects.create(
        advisory_id="VCIO-123-2002",
        datasource_id="ds",
        avid="ds/VCIO-123-2002",
        unique_content_id="i3giu",
        url="https://test.com",
        date_collected=datetime.now(),
    )
    adv1.save()

    alias = AdvisoryAlias.objects.create(alias="CVE-2021-38647")

    adv1.aliases.add(alias)

    # Run Kev Improver again when there are matching aliases.
    improver.execute()
    assert AdvisoryExploit.objects.count() == 1
