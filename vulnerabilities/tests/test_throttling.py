#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json

from django.contrib.auth.models import Permission
from django.core.cache import cache
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework.test import APITestCase
from rest_framework.throttling import AnonRateThrottle

from vulnerabilities.api import PermissionBasedUserRateThrottle
from vulnerabilities.models import ApiUser


def simulate_throttle_usage(
    url,
    client,
    mock_use_count,
    throttle_cls=PermissionBasedUserRateThrottle,
):
    throttle = throttle_cls()
    request = client.get(url).wsgi_request

    if cache_key := throttle.get_cache_key(request, view=None):
        now = throttle.timer()
        cache.set(cache_key, [now] * mock_use_count)


class PermissionBasedRateThrottleApiTests(APITestCase):
    def setUp(self):
        # Reset the api throttling to properly test the rate limit on anon users.
        # DRF stores throttling state in cache, clear cache to reset throttling.
        # See https://www.django-rest-framework.org/api-guide/throttling/#setting-up-the-cache
        cache.clear()

        permission_3600 = Permission.objects.get(codename="throttle_3600_hour")
        permission_14400 = Permission.objects.get(codename="throttle_14400_hour")
        permission_18000 = Permission.objects.get(codename="throttle_18000_hour")
        permission_unrestricted = Permission.objects.get(codename="throttle_unrestricted")

        # user with 3600/hour permission
        self.th_3600_user = ApiUser.objects.create_api_user(username="z@mail.com")
        self.th_3600_user.user_permissions.add(permission_3600)
        self.th_3600_user_auth = f"Token {self.th_3600_user.auth_token.key}"
        self.th_3600_user_csrf_client = APIClient(enforce_csrf_checks=True)
        self.th_3600_user_csrf_client.credentials(HTTP_AUTHORIZATION=self.th_3600_user_auth)

        # basic user without any special throttling perm
        self.basic_user = ApiUser.objects.create_api_user(username="a@mail.com")
        self.basic_user_auth = f"Token {self.basic_user.auth_token.key}"
        self.basic_user_csrf_client = APIClient(enforce_csrf_checks=True)
        self.basic_user_csrf_client.credentials(HTTP_AUTHORIZATION=self.basic_user_auth)

        # 14400/hour permission
        self.th_14400_user = ApiUser.objects.create_api_user(username="b@mail.com")
        self.th_14400_user.user_permissions.add(permission_14400)
        self.th_14400_user_auth = f"Token {self.th_14400_user.auth_token.key}"
        self.th_14400_user_csrf_client = APIClient(enforce_csrf_checks=True)
        self.th_14400_user_csrf_client.credentials(HTTP_AUTHORIZATION=self.th_14400_user_auth)

        # 18000/hour permission
        self.th_18000_user = ApiUser.objects.create_api_user(username="c@mail.com")
        self.th_18000_user.user_permissions.add(permission_18000)
        self.th_18000_user_auth = f"Token {self.th_18000_user.auth_token.key}"
        self.th_18000_user_csrf_client = APIClient(enforce_csrf_checks=True)
        self.th_18000_user_csrf_client.credentials(HTTP_AUTHORIZATION=self.th_18000_user_auth)

        # unrestricted throttling perm
        self.th_unrestricted_user = ApiUser.objects.create_api_user(username="d@mail.com")
        self.th_unrestricted_user.user_permissions.add(permission_unrestricted)
        self.th_unrestricted_user_auth = f"Token {self.th_unrestricted_user.auth_token.key}"
        self.th_unrestricted_user_csrf_client = APIClient(enforce_csrf_checks=True)
        self.th_unrestricted_user_csrf_client.credentials(
            HTTP_AUTHORIZATION=self.th_unrestricted_user_auth
        )

        self.csrf_client_anon = APIClient(enforce_csrf_checks=True)
        self.csrf_client_anon_1 = APIClient(enforce_csrf_checks=True)

    def test_user_with_3600_perm_throttling(self):
        simulate_throttle_usage(
            url="/api/packages",
            client=self.th_3600_user_csrf_client,
            mock_use_count=3599,
        )

        response = self.th_3600_user_csrf_client.get("/api/packages")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # exhausted 3600/hr allowed requests.
        response = self.th_3600_user_csrf_client.get("/api/packages")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_basic_user_throttling(self):
        simulate_throttle_usage(
            url="/api/packages",
            client=self.basic_user_csrf_client,
            mock_use_count=10799,
        )

        response = self.basic_user_csrf_client.get("/api/packages")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # exhausted 10800/hr allowed requests.
        response = self.basic_user_csrf_client.get("/api/packages")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_user_with_14400_perm_throttling(self):
        simulate_throttle_usage(
            url="/api/packages",
            client=self.th_14400_user_csrf_client,
            mock_use_count=14399,
        )

        response = self.th_14400_user_csrf_client.get("/api/packages")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # exhausted 14400/hr allowed requests for user with 14400 perm.
        response = self.th_14400_user_csrf_client.get("/api/packages")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_user_with_18000_perm_throttling(self):
        simulate_throttle_usage(
            url="/api/packages",
            client=self.th_18000_user_csrf_client,
            mock_use_count=17999,
        )

        response = self.th_18000_user_csrf_client.get("/api/packages")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # exhausted 18000/hr allowed requests for user with 18000 perm.
        response = self.th_18000_user_csrf_client.get("/api/packages")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_user_with_unrestricted_perm_throttling(self):
        simulate_throttle_usage(
            url="/api/packages",
            client=self.th_unrestricted_user_csrf_client,
            mock_use_count=20000,
        )

        # no throttling for user with unrestricted perm.
        response = self.th_unrestricted_user_csrf_client.get("/api/packages")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_anon_throttling(self):
        simulate_throttle_usage(
            throttle_cls=AnonRateThrottle,
            url="/api/packages",
            client=self.csrf_client_anon,
            mock_use_count=3599,
        )

        response = self.csrf_client_anon.get("/api/packages")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # exhausted 3600/hr allowed requests for anon.
        response = self.csrf_client_anon.get("/api/packages")
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(
            response.data.get("message"),
            "Your request has been throttled. Please contact support@nexb.com",
        )

        response = self.csrf_client_anon.get("/api/vulnerabilities")
        # 429 - too many requests for anon user
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(
            response.data.get("message"),
            "Your request has been throttled. Please contact support@nexb.com",
        )

        data = json.dumps({"purls": ["pkg:foo/bar"]})

        response = self.csrf_client_anon.post(
            "/api/packages/bulk_search", data=data, content_type="application/json"
        )
        # 429 - too many requests for anon user
        self.assertEqual(response.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertEqual(
            response.data.get("message"),
            "Your request has been throttled. Please contact support@nexb.com",
        )
