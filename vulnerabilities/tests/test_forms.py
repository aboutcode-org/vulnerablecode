#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.test import TestCase

from vulnerabilities.forms import VulnerabilityForm
from vulnerabilities.models import Vulnerability


class TestVulnerabilityForm(TestCase):
    def setUp(self) -> None:
        vuln1 = Vulnerability.objects.create(summary="test-vuln1", vulnerability_id="VCID-1234")
        self.id = vuln1.id

    def test_VulnerabilityForm__is_valid_with_simple_input(self):
        form = VulnerabilityForm(data={"vulnerability_id": "vcid-1234"})
        assert form.is_valid()

    def test_vulnerabilities_client(self):
        response = self.client.get(f"/vulnerabilities/{self.id}?vuln_id=vcid-1234")
        self.assertContains(response, "test-vuln1", status_code=200)
