#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest

from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference


@pytest.mark.django_db
def test_cpe_as_reference_id_in_db():
    vulnerability = Vulnerability(summary="lorem ipsum" * 10)
    vulnerability.save()
    VulnerabilityReference.objects.get_or_create(
        reference_id="cpe:2.3:a:microsoft:windows_10:10.0.17134:*:*:*:*:*:*:*" * 3,
        url="https://foo.com",
        vulnerability=vulnerability,
    )
