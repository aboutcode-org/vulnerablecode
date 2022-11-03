#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.contrib.auth import get_user_model
from rest_framework.throttling import SimpleRateThrottle

User = get_user_model()


class StaffUserRateThrottle(SimpleRateThrottle):
    def allow_request(self, request, view):
        """
        Do not apply throttling for superusers and admins.
        """
        if request.user.is_superuser or request.user.is_staff:
            return True

        return super().allow_request(request, view)

    def get_cache_key(self, request, view):
        """
        Return the cache key to use for this request.
        """
        if request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)

        return self.cache_format % {"scope": self.scope, "ident": ident}


class VulnerablePackagesAPIThrottle(StaffUserRateThrottle):
    scope = "vulnerable_packages"


class BulkSearchPackagesAPIThrottle(StaffUserRateThrottle):
    scope = "bulk_search_packages"


class PackagesAPIThrottle(StaffUserRateThrottle):
    scope = "packages"


class VulnerabilitiesAPIThrottle(StaffUserRateThrottle):
    scope = "vulnerabilities"


class AliasesAPIThrottle(StaffUserRateThrottle):
    scope = "aliases"


class CPEAPIThrottle(StaffUserRateThrottle):
    scope = "cpes"


class BulkSearchCPEAPIThrottle(StaffUserRateThrottle):
    scope = "bulk_search_cpes"
