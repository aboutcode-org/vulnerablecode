#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from io import StringIO

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase


class TestCreateApiUserCommand(TestCase):
    def test_create_simple_user(self):
        buf = StringIO()
        call_command("create_api_user", "--email", "foo@example.com", stdout=buf)
        output = buf.getvalue()
        User = get_user_model()
        user = User.objects.get(username="foo@example.com")
        assert user.email == "foo@example.com"
        assert user.auth_token.key

        assert f"User foo@example.com created with API key: {user.auth_token.key}" in output

    def test_create_simple_user_cannot_create_user_twice_with_same_email(self):
        call_command("create_api_user", "--email", "foo1@example.com")

        with pytest.raises(CommandError):
            call_command("create_api_user", "--email", "foo1@example.com")

    def test_create_user_with_names(self):
        buf = StringIO()
        call_command(
            "create_api_user",
            "--email",
            "foo3@example.com",
            "--first-name",
            "Bjorn",
            "--last-name",
            "Borg",
            stdout=buf,
        )
        User = get_user_model()
        user = User.objects.get(username="foo3@example.com")
        assert user.email == "foo3@example.com"
        assert user.auth_token.key
        assert user.first_name == "Bjorn"
        assert user.last_name == "Borg"

    def test_create_simple_user_demands_a_valid_email(self):
        with pytest.raises(CommandError):
            call_command("create_api_user", "--email", "fooNOT AN EMAIL.com")
