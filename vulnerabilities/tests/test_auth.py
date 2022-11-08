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
from django.contrib.auth.models import AnonymousUser
from django.test import TestCase

from vulnerabilities.models import ApiUser

TEST_PASSWORD = "secret"


api_package_url = "/api/packages/"
login_redirect_url = settings.LOGIN_REDIRECT_URL


class VulnerableCodeAuthTest(TestCase):
    def setUp(self):
        self.basic_user = ApiUser.objects.create_api_user(username="basic_user@foo.com")

    def test_vulnerablecode_auth_api_required_authentication(self):
        response = self.client.get(api_package_url)
        expected = {"detail": "Authentication credentials were not provided."}
        self.assertEqual(expected, response.json())
        self.assertEqual(401, response.status_code)
