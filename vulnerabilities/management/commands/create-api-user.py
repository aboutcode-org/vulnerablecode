#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import getpass

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core import exceptions
from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from rest_framework.authtoken.models import Token

"""
Create a basic API-only user based on an email.
"""


class Command(BaseCommand):
    help = "Create a basic passwordless user with an API key for sole API authentication usage."
    requires_migrations_checks = True

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.UserModel = get_user_model()
        self.username_field = self.UserModel._meta.get_field(self.UserModel.USERNAME_FIELD)

    def add_arguments(self, parser):
        parser.add_argument("--email", help="Specifies the email for the user.")
        parser.add_argument(
            "--first-name",
            default="",
            help="First name.",
        )
        parser.add_argument(
            "--last-name",
            default="",
            help="Last name.",
        )

    def handle(self, *args, **options):
        email = options["email"]
        email = self.UserModel._default_manager.normalize_email(email)
        username = email

        error_msg = self._validate_username(username)
        if error_msg:
            raise CommandError(error_msg)

        first_name = options["first_name"] or None
        last_name = options["last_name"] or None

        password = None
        user = self.UserModel._default_manager.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )
        # this esnure that this is not a valid password
        user.set_unusable_password()
        user.save()

        token, _ = Token._default_manager.get_or_create(user=user)

        msg = f"User {username} created with API key: {token.key}"
        self.stdout.write(msg, self.style.SUCCESS)

    def _validate_username(self, username):
        """
        Validate username. If invalid, return a string error message.
        """
        if self.username_field.unique:
            try:
                self.UserModel._default_manager.get_by_natural_key(username)
            except self.UserModel.DoesNotExist:
                pass
            else:
                return "Error: That email username is already taken."

        try:
            self.username_field.clean(username, None)
        except exceptions.ValidationError as e:
            return "; ".join(e.messages)
