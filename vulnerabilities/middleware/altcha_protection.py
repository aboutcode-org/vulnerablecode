#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import time
from urllib.parse import urlencode

from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin

from vulnerablecode.settings import ALTCHA_SESSION_TIMEOUT

ALTCHA_PROTECTED_PREFIXES = (
    "/packages/",
    "/advisories/",
    "/affected-by-advisories/v2/",
    "/fixing-advisories/v2/",
    "/pipelines/",
)


class AltchaProtectionMiddleware(MiddlewareMixin):
    def __call__(self, request):
        if not ALTCHA_SESSION_TIMEOUT:
            return self.get_response(request)

        protected = any(request.path.startswith(prefix) for prefix in ALTCHA_PROTECTED_PREFIXES)

        if not protected:
            return self.get_response(request)

        verified_at = request.session.get("altcha_verified_at")
        next_url = request.get_full_path()

        if not verified_at:
            return redirect(f"/altcha/?{urlencode({'next': next_url})}")

        if time.time() - verified_at > ALTCHA_SESSION_TIMEOUT:
            request.session.pop("altcha_verified_at", None)
            return redirect(f"/altcha/?{urlencode({'next': next_url})}")

        return self.get_response(request)
