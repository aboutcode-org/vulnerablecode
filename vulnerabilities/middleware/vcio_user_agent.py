#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.conf import settings
from django.http import JsonResponse


class VCIOUserAgentMiddleware:
    """
    Allow API access only when the User-Agent matches VCIO_USER_AGENT.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith("/api/") and not request.path.startswith(
            ("/api/docs/", "/api/schema/")
        ):
            user_agent = request.headers.get("User-Agent", "")
            docs_url = request.build_absolute_uri("/api/docs/")
            if user_agent != settings.VCIO_USER_AGENT:
                return JsonResponse(
                    {
                        "detail": (
                            "Unauthorized client. Please refer to the API "
                            "documentation at "
                            f"{docs_url}"
                        )
                    },
                    status=403,
                )

        return self.get_response(request)
