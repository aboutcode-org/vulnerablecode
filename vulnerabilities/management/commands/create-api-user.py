#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.core import exceptions
from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from django.core.validators import validate_email

from vulnerabilities.models import ApiUser

"""
Create a basic API-only user based on an email.
"""


class Command(BaseCommand):
    help = "Create a basic passwordless user with an API key for sole API authentication usage."
    requires_migrations_checks = True

    def add_arguments(self, parser):
        parser.add_argument(
            "--email",
            help="Specifies the email for the user.",
        )
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
        try:
            validate_email(email)
            user = ApiUser.objects.create_api_user(
                username=email,
                first_name=options["first_name"] or "",
                last_name=options["last_name"] or "",
            )
        except exceptions.ValidationError as e:
            raise CommandError(str(e))

        msg = f"User {user.email} created with API key: {user.auth_token.key}"
        self.stdout.write(msg, self.style.SUCCESS)
