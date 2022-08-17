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
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.mixins import UserPassesTestMixin


def is_authenticated_when_required(user):
    """
    Returns True if the `user` is authenticated when the
    `VULNERABLECODEIO_REQUIRE_AUTHENTICATION` setting is enabled.
    Always True when the Authentication is not enabled.
    """
    if not settings.VULNERABLECODEIO_REQUIRE_AUTHENTICATION:
        return True

    if user.is_authenticated:
        return True

    return False


def conditional_login_required(function=None):
    """
    Decorator for views that checks that the current user is authenticated when
    authentication is enabled.
    """
    actual_decorator = user_passes_test(is_authenticated_when_required)
    if function:
        return actual_decorator(function)
    return actual_decorator


class ConditionalLoginRequired(UserPassesTestMixin):
    """
    CBV mixin for views that checks that the current user is authenticated when
    authentication is enabled.
    """

    def test_func(self):
        return is_authenticated_when_required(self.request.user)
