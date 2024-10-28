#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.http import HttpResponseNotFound
from django.utils.deprecation import MiddlewareMixin


class BanUserAgent(MiddlewareMixin):
    def process_request(self, request):
        user_agent = request.META.get("HTTP_USER_AGENT", None)
        if user_agent and "bytedance" in user_agent:
            return HttpResponseNotFound(404)
