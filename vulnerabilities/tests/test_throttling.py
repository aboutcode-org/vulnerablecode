#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json

from rest_framework.test import APIClient
from rest_framework.test import APITestCase

from vulnerabilities.models import ApiUser


class ThrottleApiTests(APITestCase):
    def setUp(self):
        # create a basic user
        self.user = ApiUser.objects.create_api_user(username="e@mail.com")
        self.auth = f"Token {self.user.auth_token.key}"
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.csrf_client.credentials(HTTP_AUTHORIZATION=self.auth)

        # create a staff user
        self.staff_user = ApiUser.objects.create_api_user(username="staff@mail.com", is_staff=True)
        self.staff_auth = f"Token {self.staff_user.auth_token.key}"
        self.staff_csrf_client = APIClient(enforce_csrf_checks=True)
        self.staff_csrf_client.credentials(HTTP_AUTHORIZATION=self.staff_auth)

        self.csrf_client_anon = APIClient(enforce_csrf_checks=True)
        self.csrf_client_anon_1 = APIClient(enforce_csrf_checks=True)

    def test_package_endpoint_throttling(self):
        for i in range(0, 20):
            response = self.csrf_client.get("/api/packages")
            self.assertEqual(response.status_code, 200)
            response = self.staff_csrf_client.get("/api/packages")
            self.assertEqual(response.status_code, 200)

        response = self.csrf_client.get("/api/packages")
        # 429 - too many requests for basic user
        self.assertEqual(response.status_code, 429)

        response = self.staff_csrf_client.get("/api/packages", format="json")
        # 200 - staff user can access API unlimited times
        self.assertEqual(response.status_code, 200)

        # A anonymous user can only access /packages endpoint 10 times a day
        for _i in range(0, 10):
            response = self.csrf_client_anon.get("/api/packages")
            self.assertEqual(response.status_code, 200)

        response = self.csrf_client_anon.get("/api/packages")
        # 429 - too many requests for anon user
        self.assertEqual(response.status_code, 429)
        self.assertEqual(
            response.data.get("message"),
            "Your request has been throttled. Please contact support@nexb.com",
        )

        response = self.csrf_client_anon.get("/api/vulnerabilities")
        # 429 - too many requests for anon user
        self.assertEqual(response.status_code, 429)
        self.assertEqual(
            response.data.get("message"),
            "Your request has been throttled. Please contact support@nexb.com",
        )

        data = json.dumps({"purls": ["pkg:foo/bar"]})

        response = self.csrf_client_anon.post(
            "/api/packages/bulk_search", data=data, content_type="application/json"
        )
        # 429 - too many requests for anon user
        self.assertEqual(response.status_code, 429)
        self.assertEqual(
            response.data.get("message"),
            "Your request has been throttled. Please contact support@nexb.com",
        )
