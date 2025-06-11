#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json

from django.contrib.auth.models import Group
from django.core.cache import cache
from rest_framework.test import APIClient
from rest_framework.test import APITestCase

from vulnerabilities.models import ApiUser


class GroupUserRateThrottleApiTests(APITestCase):
    def setUp(self):
        # Reset the api throttling to properly test the rate limit on anon users.
        # DRF stores throttling state in cache, clear cache to reset throttling.
        # See https://www.django-rest-framework.org/api-guide/throttling/#setting-up-the-cache
        cache.clear()

        # User in bronze group
        self.bronze_user = ApiUser.objects.create_api_user(username="bronze@mail.com")
        bronze, _ = Group.objects.get_or_create(name="bronze")
        self.bronze_user.groups.clear()
        self.bronze_user.groups.add(bronze)
        self.bronze_auth = f"Token {self.bronze_user.auth_token.key}"
        self.bronze_user_csrf_client = APIClient(enforce_csrf_checks=True)
        self.bronze_user_csrf_client.credentials(HTTP_AUTHORIZATION=self.bronze_auth)

        # User in silver group (default group for api user)
        self.silver_user = ApiUser.objects.create_api_user(username="silver@mail.com")
        self.silver_auth = f"Token {self.silver_user.auth_token.key}"
        self.silver_user_csrf_client = APIClient(enforce_csrf_checks=True)
        self.silver_user_csrf_client.credentials(HTTP_AUTHORIZATION=self.silver_auth)

        # User in gold group
        self.gold_user = ApiUser.objects.create_api_user(username="gold@mail.com")
        gold, _ = Group.objects.get_or_create(name="gold")
        self.gold_user.groups.add(gold)
        self.gold_auth = f"Token {self.gold_user.auth_token.key}"
        self.gold_user_csrf_client = APIClient(enforce_csrf_checks=True)
        self.gold_user_csrf_client.credentials(HTTP_AUTHORIZATION=self.gold_auth)

        # create a staff user
        self.staff_user = ApiUser.objects.create_api_user(username="staff@mail.com", is_staff=True)
        self.staff_auth = f"Token {self.staff_user.auth_token.key}"
        self.staff_csrf_client = APIClient(enforce_csrf_checks=True)
        self.staff_csrf_client.credentials(HTTP_AUTHORIZATION=self.staff_auth)

        self.csrf_client_anon = APIClient(enforce_csrf_checks=True)
        self.csrf_client_anon_1 = APIClient(enforce_csrf_checks=True)

    def test_package_endpoint_throttling(self):
        for i in range(0, 15):
            response = self.bronze_user_csrf_client.get("/api/packages")
            self.assertEqual(response.status_code, 200)

        response = self.bronze_user_csrf_client.get("/api/packages")
        # 429 - too many requests for bronze user
        self.assertEqual(response.status_code, 429)

        for i in range(0, 20):
            response = self.silver_user_csrf_client.get("/api/packages")
            self.assertEqual(response.status_code, 200)

        response = self.silver_user_csrf_client.get("/api/packages")
        # 429 - too many requests for silver user
        self.assertEqual(response.status_code, 429)

        for i in range(0, 30):
            response = self.gold_user_csrf_client.get("/api/packages")
            self.assertEqual(response.status_code, 200)

        response = self.gold_user_csrf_client.get("/api/packages", format="json")
        # 200 - gold user can access API unlimited times
        self.assertEqual(response.status_code, 200)

        for i in range(0, 30):
            response = self.staff_csrf_client.get("/api/packages")
            self.assertEqual(response.status_code, 200)

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
