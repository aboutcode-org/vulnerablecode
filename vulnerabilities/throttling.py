#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from rest_framework.exceptions import Throttled
from rest_framework.throttling import UserRateThrottle
from rest_framework.views import exception_handler


class PermissionBasedUserRateThrottle(UserRateThrottle):
    def allow_request(self, request, view):
        user = request.user

        if user and user.is_authenticated:
            if user.has_perm("vulnerabilities.throttle_unrestricted"):
                return True
            elif user.has_perm("vulnerabilities.throttle_18000_hour"):
                self.rate = "18000/hour"
            elif user.has_perm("vulnerabilities.throttle_14400_hour"):
                self.rate = "14400/hour"

            self.num_requests, self.duration = self.parse_rate(self.rate)

        return super().allow_request(request, view)


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
