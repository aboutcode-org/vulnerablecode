#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.contrib.auth import get_user_model
from rest_framework.throttling import UserRateThrottle

User = get_user_model()


class StaffUserRateThrottle(UserRateThrottle):
    def allow_request(self, request, view):
        """
        Do not apply throttling for superusers and admins.
        """
        if request.user.is_superuser or request.user.is_staff:
            return True

        return super().allow_request(request, view)
