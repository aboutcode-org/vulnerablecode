#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

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

    def test_api_throttling(self):

        # A basic user can only access API 5 times a day
        for i in range(0, 5):
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
