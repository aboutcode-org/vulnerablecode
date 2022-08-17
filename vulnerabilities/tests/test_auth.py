#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
# This is copied from https://github.com/nexB/scancode.io/commit/eab8eeb13989c26a1600cc64e8b054f171341063
#

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import TestCase
from django.test import override_settings
from django.urls import reverse

from vulnerablecode.auth import is_authenticated_when_required

TEST_PASSWORD = "secret"

User = get_user_model()

login_url = reverse("login")
logout_url = reverse("logout")
profile_url = reverse("account_profile")
api_package_url = "/api/packages/"
login_redirect_url = settings.LOGIN_REDIRECT_URL


class VulnerableCodeAuthTest(TestCase):
    def setUp(self):
        self.anonymous_user = AnonymousUser()
        self.basic_user = User.objects.create_user(username="basic_user", password=TEST_PASSWORD)

    def test_vulnerablecode_auth_is_authenticated_when_required(self):
        with override_settings(VULNERABLECODEIO_REQUIRE_AUTHENTICATION=True):
            self.assertFalse(self.anonymous_user.is_authenticated)
            self.assertFalse(is_authenticated_when_required(user=self.anonymous_user))

        self.assertTrue(self.basic_user.is_authenticated)
        self.assertTrue(is_authenticated_when_required(user=self.basic_user))

        with override_settings(VULNERABLECODEIO_REQUIRE_AUTHENTICATION=False):
            self.assertTrue(is_authenticated_when_required(user=None))

    def test_vulnerablecode_auth_login_view(self):
        data = {"username": self.basic_user.username, "password": ""}
        response = self.client.post(login_url, data)
        form = response.context_data["form"]
        expected_error = {"password": ["This field is required."]}
        self.assertEqual(expected_error, form.errors)

        data = {"username": self.basic_user.username, "password": "wrong"}
        response = self.client.post(login_url, data)
        form = response.context_data["form"]
        expected_error = {
            "__all__": [
                "Please enter a correct username and password. "
                "Note that both fields may be case-sensitive."
            ]
        }
        self.assertEqual(expected_error, form.errors)

        data = {"username": self.basic_user.username, "password": TEST_PASSWORD}
        response = self.client.post(login_url, data, follow=True)
        self.assertRedirects(response, login_redirect_url)
        expected = '<a class="navbar-link">basic_user</a>'
        self.assertContains(response, expected, html=True)

    def test_vulnerablecode_auth_logout_view(self):
        response = self.client.get(logout_url)
        self.assertRedirects(response, login_url)

        self.client.login(username=self.basic_user.username, password=TEST_PASSWORD)
        response = self.client.get(logout_url)
        self.assertRedirects(response, login_url)

    def test_vulnerablecode_account_profile_view(self):
        self.client.login(username=self.basic_user.username, password=TEST_PASSWORD)
        response = self.client.get(profile_url)
        expected = '<label class="label">API Key</label>'
        self.assertContains(response, expected, html=True)
        expected = '<label class="label">API Key</label>'
        self.assertContains(response, self.basic_user.auth_token.key)

    def test_vulnerablecode_auth_api_required_authentication(self):
        with override_settings(VULNERABLECODEIO_REQUIRE_AUTHENTICATION=True):
            response = self.client.get(api_package_url)
            expected = {"detail": "Authentication credentials were not provided."}
            self.assertEqual(expected, response.json())
            self.assertEqual(401, response.status_code)
