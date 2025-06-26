#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.core.exceptions import ImproperlyConfigured
from rest_framework.exceptions import Throttled
from rest_framework.throttling import UserRateThrottle
from rest_framework.views import exception_handler


class PermissionBasedUserRateThrottle(UserRateThrottle):
    """
    Throttles authenticated users based on their assigned permissions.
    If no throttling permission is assigned, defaults to `medium` throttling
    for authenticated users and `anon` for unauthenticated users.
    """

    def __init__(self):
        pass

    def allow_request(self, request, view):
        user = request.user
        throttling_tier = "medium"

        if not user or not user.is_authenticated:
            throttling_tier = "anon"
        elif user.has_perm("vulnerabilities.throttle_3_unrestricted"):
            return True
        elif user.has_perm("vulnerabilities.throttle_2_high"):
            throttling_tier = "high"
        elif user.has_perm("vulnerabilities.throttle_1_medium"):
            throttling_tier = "medium"
        elif user.has_perm("vulnerabilities.throttle_0_low"):
            throttling_tier = "low"

        self.rate = self.get_throttle_rate(throttling_tier)
        self.num_requests, self.duration = self.parse_rate(self.rate)

        return super().allow_request(request, view)

    def get_throttle_rate(self, tier):
        try:
            return self.THROTTLE_RATES[tier]
        except KeyError:
            msg = f"No throttle rate set for {tier}."
            raise ImproperlyConfigured(msg)


def throttled_exception_handler(exception, context):
    """
    Return this response whenever a request has been throttled
    """

    response = exception_handler(exception, context)

    if isinstance(exception, Throttled):
        response_data = {
            "message": "Your request has been throttled. Please contact support@nexb.com"
        }
        response.data = response_data

    return response
