#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import time

import pytest
from django.urls import reverse

INVALID_AVID = "pysec/PYSEC-3000-0"


@pytest.mark.django_db
@pytest.mark.parametrize(
    "url_name",
    [
        "advisory_details",
        "advisory_package_details",
        "advisory_package_commit_details",
    ],
)
def test_advisory_views_return_404_for_invalid_avid(client, url_name):
    """
    Requesting an advisory-related page for an avid that does not exist should
    return a 404 Page Not Found, not a 500 Server Error.

    Regression test for: "Advisory Page Returns 500 Instead of 404 for Invalid
    Advisory IDs".
    """
    # Satisfy AltchaProtectionMiddleware so the request reaches the view
    # instead of being redirected to the captcha page.
    session = client.session
    session["altcha_verified_at"] = time.time()
    session.save()

    url = reverse(url_name, kwargs={"avid": INVALID_AVID})
    response = client.get(url)

    assert response.status_code == 404
