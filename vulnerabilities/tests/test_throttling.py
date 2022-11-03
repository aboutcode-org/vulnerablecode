#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json

from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from rest_framework.test import APITestCase

User = get_user_model()


class ThrottleApiTests(APITestCase):
    def setUp(self):
        # create a basic user
        self.user = User.objects.create_user("username", "e@mail.com", "secret")
        self.auth = f"Token {self.user.auth_token.key}"
        self.csrf_client = APIClient(enforce_csrf_checks=True)
        self.csrf_client.credentials(HTTP_AUTHORIZATION=self.auth)

        # create a staff user
        self.staff_user = User.objects.create_user(
            "staff", "staff@mail.com", "secret", is_staff=True
        )
        self.staff_auth = f"Token {self.staff_user.auth_token.key}"
        self.staff_csrf_client = APIClient(enforce_csrf_checks=True)
        self.staff_csrf_client.credentials(HTTP_AUTHORIZATION=self.staff_auth)

    def test_packages_endpoint_throttling(self):

        # A basic user can only access /packages endpoint 10 times a day
        for i in range(0, 10):
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

    def test_cpes_endpoint_throttling(self):

        # A basic user can only access /cpes endpoint 4 times a day
        for i in range(0, 4):
            response = self.csrf_client.get("/api/cpes")
            self.assertEqual(response.status_code, 200)
            response = self.staff_csrf_client.get("/api/cpes")
            self.assertEqual(response.status_code, 200)

        response = self.csrf_client.get("/api/cpes")
        # 429 - too many requests for basic user
        self.assertEqual(response.status_code, 429)

        response = self.staff_csrf_client.get("/api/cpes", format="json")
        # 200 - staff user can access API unlimited times
        self.assertEqual(response.status_code, 200)

    def test_all_vulnerable_packages_endpoint_throttling(self):

        # A basic user can only access /packages/all 1 time a day
        for i in range(0, 1):
            response = self.csrf_client.get("/api/packages/all")
            self.assertEqual(response.status_code, 200)
            response = self.staff_csrf_client.get("/api/packages/all")
            self.assertEqual(response.status_code, 200)

        response = self.csrf_client.get("/api/packages/all")
        # 429 - too many requests for basic user
        self.assertEqual(response.status_code, 429)

        response = self.staff_csrf_client.get("/api/packages/all", format="json")
        # 200 - staff user can access API unlimited times
        self.assertEqual(response.status_code, 200)

    def test_vulnerabilities_endpoint_throttling(self):

        # A basic user can only access /vulnerabilities 8 times a day
        for i in range(0, 8):
            response = self.csrf_client.get("/api/vulnerabilities")
            self.assertEqual(response.status_code, 200)
            response = self.staff_csrf_client.get("/api/vulnerabilities")
            self.assertEqual(response.status_code, 200)

        response = self.csrf_client.get("/api/vulnerabilities")
        # 429 - too many requests for basic user
        self.assertEqual(response.status_code, 429)

        response = self.staff_csrf_client.get("/api/vulnerabilities", format="json")
        # 200 - staff user can access API unlimited times
        self.assertEqual(response.status_code, 200)

    def test_aliases_endpoint_throttling(self):

        # A basic user can only access /alias 2 times a day
        for i in range(0, 2):
            response = self.csrf_client.get("/api/alias")
            self.assertEqual(response.status_code, 200)
            response = self.staff_csrf_client.get("/api/alias")
            self.assertEqual(response.status_code, 200)

        response = self.csrf_client.get("/api/alias")
        # 429 - too many requests for basic user
        self.assertEqual(response.status_code, 429)

        response = self.staff_csrf_client.get("/api/alias", format="json")
        # 200 - staff user can access API unlimited times
        self.assertEqual(response.status_code, 200)

    def test_bulk_search_packages_endpoint_throttling(self):
        data = json.dumps({"purls": ["pkg:foo/bar"]})

        # A basic user can only access /packages/bulk_search 6 times a day
        for i in range(0, 6):
            response = self.csrf_client.post(
                "/api/packages/bulk_search", data=data, content_type="application/json"
            )
            self.assertEqual(response.status_code, 200)
            response = self.staff_csrf_client.post(
                "/api/packages/bulk_search", data=data, content_type="application/json"
            )
            self.assertEqual(response.status_code, 200)

        response = self.csrf_client.post(
            "/api/packages/bulk_search", data=data, content_type="application/json"
        )
        # 429 - too many requests for basic user
        self.assertEqual(response.status_code, 429)

        response = self.staff_csrf_client.post(
            "/api/packages/bulk_search", data=data, content_type="application/json"
        )
        # 200 - staff user can access API unlimited times
        self.assertEqual(response.status_code, 200)

    def test_bulk_search_cpes_endpoint_throttling(self):
        data = json.dumps({"cpes": ["cpe:foo/bar"]})

        # A basic user can only access /cpes/bulk_search 5 times a day
        for i in range(0, 5):
            response = self.csrf_client.post(
                "/api/cpes/bulk_search", data=data, content_type="application/json"
            )
            self.assertEqual(response.status_code, 200)
            response = self.staff_csrf_client.post(
                "/api/cpes/bulk_search", data=data, content_type="application/json"
            )
            self.assertEqual(response.status_code, 200)

        response = self.csrf_client.post(
            "/api/cpes/bulk_search", data=data, content_type="application/json"
        )
        # 429 - too many requests for basic user
        self.assertEqual(response.status_code, 429)

        response = self.staff_csrf_client.post(
            "/api/cpes/bulk_search", data=data, content_type="application/json"
        )
        # 200 - staff user can access API unlimited times
        self.assertEqual(response.status_code, 200)
