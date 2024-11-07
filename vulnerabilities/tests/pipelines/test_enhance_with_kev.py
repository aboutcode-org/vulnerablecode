#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from unittest import mock
from unittest.mock import Mock

import pytest

from vulnerabilities.models import Alias
from vulnerabilities.models import Exploit
from vulnerabilities.models import Vulnerability
from vulnerabilities.pipelines.enhance_with_kev import VulnerabilityKevPipeline
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

    assert Exploit.objects.count() == 0

    v1 = Vulnerability.objects.create(vulnerability_id="VCIO-123-2002")
    v1.save()

    Alias.objects.create(alias="CVE-2021-38647", vulnerability=v1)

    # Run Kev Improver again when there are matching aliases.
    improver.execute()
    assert Exploit.objects.count() == 1
