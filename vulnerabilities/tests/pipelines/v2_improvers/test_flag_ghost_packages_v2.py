#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import patch

import pytest
from packageurl import PackageURL

from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines.v2_improvers.flag_ghost_packages import (
    detect_and_flag_ghost_packages,
)
from vulnerabilities.pipelines.v2_improvers.flag_ghost_packages import flag_ghost_packages


@pytest.mark.django_db
def test_flag_ghost_package_marked_correctly():
    pkg = PackageV2.objects.create(
        type="pypi",
        namespace=None,
        name="requests",
        version="999.999.999",
    )

    with patch(
        "vulnerabilities.pipelines.v2_improvers.flag_ghost_packages.get_versions"
    ) as mock_get_versions:
        mock_get_versions.return_value = {"2.25.1", "2.26.0"}

        base_purl = PackageURL(type="pypi", namespace=None, name="requests")
        ghost_count = flag_ghost_packages(base_purl, [pkg])

        pkg.refresh_from_db()
        assert ghost_count == 1
        assert pkg.is_ghost is True


@pytest.mark.django_db
def test_flag_non_ghost_package_not_marked():
    pkg = PackageV2.objects.create(
        type="pypi",
        namespace=None,
        name="requests",
        version="2.26.0",
    )

    with patch(
        "vulnerabilities.pipelines.v2_improvers.flag_ghost_packages.get_versions"
    ) as mock_get_versions:
        mock_get_versions.return_value = {"2.25.1", "2.26.0"}

        base_purl = PackageURL(type="pypi", namespace=None, name="requests")
        ghost_count = flag_ghost_packages(base_purl, [pkg])

        pkg.refresh_from_db()
        assert ghost_count == 0
        assert pkg.is_ghost is False


@pytest.mark.django_db
def test_flag_ghost_packages_gracefully_handles_version_fetch_failure():
    pkg = PackageV2.objects.create(
        type="pypi",
        namespace=None,
        name="some-lib",
        version="1.0.0",
    )

    with patch(
        "vulnerabilities.pipelines.v2_improvers.flag_ghost_packages.get_versions"
    ) as mock_get_versions:
        mock_get_versions.return_value = None

        base_purl = PackageURL(type="pypi", namespace=None, name="some-lib")
        ghost_count = flag_ghost_packages(base_purl, [pkg])

        pkg.refresh_from_db()
        assert ghost_count == 0
        assert pkg.is_ghost is False


@pytest.mark.django_db
def test_detect_and_flag_ghost_packages(monkeypatch):
    ghost_pkg = PackageV2.objects.create(type="pypi", name="fakepkg", version="9.9.9")
    real_pkg = PackageV2.objects.create(type="pypi", name="realpkg", version="1.0.0")

    def fake_versions(purl, logger=None):
        if purl.name == "realpkg":
            return {"1.0.0"}
        if purl.name == "fakepkg":
            return {"0.1.0", "0.2.0"}
        return set()

    monkeypatch.setattr(
        "vulnerabilities.pipelines.v2_improvers.flag_ghost_packages.get_versions",
        fake_versions,
    )

    detect_and_flag_ghost_packages()

    ghost_pkg.refresh_from_db()
    real_pkg.refresh_from_db()

    assert ghost_pkg.is_ghost is True
    assert real_pkg.is_ghost is False
