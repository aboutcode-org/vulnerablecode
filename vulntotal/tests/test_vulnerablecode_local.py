#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from typing import List

import pytest
from packageurl import PackageURL

from vulntotal.datasources.vulnerablecode_local import LocalVulnerableCodeDataSource


class FakeResponse:
    def __init__(self, status_code=200, json_data=None, text=""):
        self.status_code = status_code
        self._json = json_data
        self.text = text or ("" if json_data is None else str(json_data))

    def json(self):
        return self._json


def make_v2_advisories_response(
    pkg_purl: str, advisory_id: str, aliases: List[str], fixes: List[str]
):
    return {
        "packages": [
            {
                "purl": pkg_purl,
                "affected_by_vulnerabilities": {
                    "live_v2_importer_name/"
                    + advisory_id: {
                        "advisory_id": "live_v2_importer_name/" + advisory_id,
                        "fixed_by_packages": fixes,
                        "code_fixes": [],
                    }
                },
            }
        ],
        "advisories": {
            advisory_id: {
                "advisory_id": "live_v2_importer_name/" + advisory_id,
                "aliases": aliases,
            }
        },
    }


def test_local_vulnerablecode_v2_bulk_search_and_vendor_data(monkeypatch):
    monkeypatch.setenv("VCIO_HOST", "localhost")
    monkeypatch.setenv("VCIO_PORT", "1234")
    monkeypatch.setenv("ENABLE_LIVE_EVAL", "0")

    calls = []

    def fake_post(url, json=None, **kwargs):
        calls.append((url, json))
        if url.endswith("/api/v2/advisories-packages/bulk_search/"):
            return FakeResponse(
                200,
                make_v2_advisories_response(
                    pkg_purl="pkg:pypi/demo@1.2.3",
                    advisory_id="ADV-123",
                    aliases=["CVE-2024-0001", "GHSA-foo"],
                    fixes=["pkg:pypi/demo@1.2.4", "pkg:pypi/demo@1.3.0"],
                ),
            )

        return FakeResponse(404, {"detail": "not found"})

    monkeypatch.setattr("vulntotal.datasources.vulnerablecode_local.requests.post", fake_post)

    ds = LocalVulnerableCodeDataSource()
    purl = PackageURL.from_string("pkg:pypi/demo@1.2.3")

    results = list(ds.datasource_advisory(purl))

    assert any(
        "/api/v2/advisories-packages/bulk_search/" in url for url, _ in calls
    ), "v2 advisories bulk_search should be called"

    assert not any(
        "/api/v2/live-evaluation/evaluate" in url for url, _ in calls
    ), "live evaluation should not be called when disabled"

    assert len(results) == 1
    vd = results[0].to_dict()
    assert vd["purl"] == "pkg:pypi/demo"
    assert vd["aliases"] == ["CVE-2024-0001", "GHSA-foo"]
    assert vd["affected_versions"] == ["1.2.3"]
    assert sorted(vd["fixed_versions"]) == ["1.2.4", "1.3.0"]


def test_local_vulnerablecode_triggers_live_evaluation_when_enabled(monkeypatch):
    monkeypatch.setenv("VCIO_HOST", "localhost")
    monkeypatch.setenv("VCIO_PORT", "1234")
    monkeypatch.setenv("ENABLE_LIVE_EVAL", "1")

    calls = []

    def fake_post(url, json=None, **kwargs):  # noqa: A002 (shadowing builtins)
        calls.append((url, json))
        if url.endswith("/api/v2/live-evaluation/evaluate"):
            return FakeResponse(202, {"status": "accepted"})
        if url.endswith("/api/v2/advisories-packages/bulk_search/"):
            return FakeResponse(
                200,
                make_v2_advisories_response(
                    pkg_purl="pkg:pypi/demo@1.2.3",
                    advisory_id="ADV-999",
                    aliases=["CVE-2025-1111"],
                    fixes=["pkg:pypi/demo@1.2.5"],
                ),
            )
        return FakeResponse(404, {"detail": "not found"})

    monkeypatch.setattr("vulntotal.datasources.vulnerablecode_local.requests.post", fake_post)

    ds = LocalVulnerableCodeDataSource()
    purl = PackageURL.from_string("pkg:pypi/demo@1.2.3")

    results = list(ds.datasource_advisory(purl))

    urls = [u for u, _ in calls]
    assert any(
        "/api/v2/live-evaluation/evaluate" in url for url in urls
    ), "live evaluation endpoint should be called when enabled"
    assert any(
        "/api/v2/advisories-packages/bulk_search/" in url for url in urls
    ), "v2 advisories bulk_search should be called"

    assert len(results) == 1
    vd = results[0].to_dict()
    assert vd["aliases"] == ["CVE-2025-1111"]
    assert vd["affected_versions"] == ["1.2.3"]
    assert vd["fixed_versions"] == ["1.2.5"]
