#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.test import TestCase

from vulnerabilities.forms import VulnerabilitySearchForm
from vulnerabilities.models import Vulnerability


class TestVulnerabilitySearchForm(TestCase):
    def setUp(self) -> None:
        self.vulnerability = Vulnerability.objects.create(
            vulnerability_id="VCID-1234",
            summary="test-vuln1",
        )

    def test_VulnerabilitySearchForm__is_valid_with_simple_input(self):
        form = VulnerabilitySearchForm(data={"search": "vcid-1234"})
        assert form.is_valid()

    def test_vulnerabilities_search_view_can_lookup_by_vcid(self):
        vcid = self.vulnerability.vulnerability_id
        response = self.client.get(f"/vulnerabilities/{vcid}?search=vcid-1234")
        self.assertContains(response, "test-vuln1", status_code=200)

    def test_vulnerabilities_search_view_does_not_work_by_pk(self):
        pk = self.vulnerability.pk
        response = self.client.get(f"/vulnerabilities/{pk}")
        self.assertEqual(response.status_code, 404)
