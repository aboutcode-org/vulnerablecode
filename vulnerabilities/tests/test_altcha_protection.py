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
from django.test import RequestFactory

from vulnerabilities.forms import AltchaForm


@pytest.mark.django_db
class TestAltchaProtectionMiddleware:
    def test_protected_url_redirects_without_session(self, client):
        response = client.get("/packages/search/")

        assert response.status_code == 302
        assert response.url == "/altcha/?next=%2Fpackages%2Fsearch%2F"

    def test_unprotected_url_is_accessible(self, client):
        response = client.get("/")

        assert response.status_code != 302

    def test_protected_url_allowed_with_valid_session(self, client):
        session = client.session
        session["altcha_verified_at"] = time.time()
        session.save()

        response = client.get("/packages/search/")

        assert response.status_code != 302

    def test_expired_session_redirects(self, client):

        session = client.session
        session["altcha_verified_at"] = time.time() - 3601
        session.save()

        response = client.get("/packages/search/")

        assert response.status_code == 302
        assert response.url == "/altcha/?next=%2Fpackages%2Fsearch%2F"

    def test_expired_session_is_removed(self, client):
        session = client.session
        session["altcha_verified_at"] = time.time() - 3601
        session.save()

        client.get("/packages/search/")

        session = client.session
        assert "altcha_verified_at" not in session


@pytest.mark.django_db
class TestAltchaView:
    def test_form_valid_sets_session(self, monkeypatch):
        from vulnerabilities.views import AltchaView

        now = 1234567890

        monkeypatch.setattr(time, "time", lambda: now)

        request = RequestFactory().get("/altcha/")
        request.session = {}

        view = AltchaView()
        view.request = request

        response = view.form_valid(AltchaForm())

        assert response.status_code == 302
        assert response.url == "/"
        assert request.session["altcha_verified_at"] == now
