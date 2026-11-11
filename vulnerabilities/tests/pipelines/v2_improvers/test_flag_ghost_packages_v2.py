#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from unittest.mock import Mock
from unittest.mock import patch

import pytest
from fetchcode.package_versions import PackageVersion
from packageurl import PackageURL
from requests import HTTPError
from requests import Response
from requests import Timeout

from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines.v2_improvers.flag_ghost_packages import PackageNotFoundError
from vulnerabilities.pipelines.v2_improvers.flag_ghost_packages import (
    detect_and_flag_ghost_packages,
)
from vulnerabilities.pipelines.v2_improvers.flag_ghost_packages import flag_ghost_packages
from vulnerabilities.pipelines.v2_improvers.flag_ghost_packages import get_versions


@pytest.mark.django_db
def test_flag_ghost_package_version_marked_correctly():
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
        logger = Mock()
        counts = flag_ghost_packages(base_purl, [pkg], logger=logger)

        pkg.refresh_from_db()
        assert pkg.is_ghost is True
        logger.assert_called_once_with(
            "Flagging ghost package version pkg:pypi/requests@999.999.999 for PurlDB verification",
            level=logging.INFO,
        )
        assert counts.packages == 0
        assert counts.versions == 1


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
        counts = flag_ghost_packages(base_purl, [pkg])

        pkg.refresh_from_db()
        assert counts.packages == 0
        assert counts.versions == 0
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
        counts = flag_ghost_packages(base_purl, [pkg])

        pkg.refresh_from_db()
        assert counts.packages == 0
        assert counts.versions == 0
        assert pkg.is_ghost is False


@pytest.mark.django_db
def test_detect_and_flag_ghost_packages(monkeypatch):
    ghost_pkg = PackageV2.objects.create(type="pypi", name="fakepkg", version="9.9.9")
    missing_pkg = PackageV2.objects.from_purl("pkg:pypi/missing@1.0.0")
    missing_pkg2 = PackageV2.objects.from_purl("pkg:pypi/missing@2.0.0")
    real_pkg = PackageV2.objects.create(type="pypi", name="realpkg", version="1.0.0")

    def fake_versions(purl):
        if purl == "pkg:pypi/realpkg":
            return [PackageVersion(value="1.0.0")]
        if purl == "pkg:pypi/fakepkg":
            return [PackageVersion(value="0.1.0"), PackageVersion(value="0.2.0")]
        if purl == "pkg:pypi/missing":
            raise registry_error(404)
        raise AssertionError(f"Unexpected registry lookup: {purl}")

    monkeypatch.setattr(
        "vulnerabilities.pipelines.v2_improvers.flag_ghost_packages.versions",
        fake_versions,
    )

    logger = Mock()
    detect_and_flag_ghost_packages(logger=logger)

    ghost_pkg.refresh_from_db()
    missing_pkg.refresh_from_db()
    missing_pkg2.refresh_from_db()
    real_pkg.refresh_from_db()

    assert ghost_pkg.is_ghost is True
    assert missing_pkg.is_ghost is True
    assert missing_pkg2.is_ghost is True
    assert real_pkg.is_ghost is False
    logger.assert_any_call("Successfully flagged 1 ghost packages and 1 ghost package versions")


def registry_error(status_code, url="https://pypi.org/pypi/missing/json"):
    response = Response()
    response.status_code = status_code
    response.url = url
    return HTTPError(response=response)


@pytest.mark.parametrize("purl", ["pkg:pypi/missing", PackageURL(type="pypi", name="missing")])
@patch("vulnerabilities.pipelines.v2_improvers.flag_ghost_packages.versions")
def test_package_level_404_is_distinct_from_lookup_failure(mock_versions, purl):
    mock_versions.side_effect = registry_error(404)
    logger = Mock()

    with pytest.raises(PackageNotFoundError):
        get_versions(purl, logger=logger)

    logger.assert_not_called()


@pytest.mark.django_db
@patch("vulnerabilities.pipelines.v2_improvers.flag_ghost_packages.versions")
def test_missing_package_is_reported_once_for_all_versions(mock_versions):
    packages = [
        PackageV2.objects.from_purl("pkg:pypi/missing@1.0.0"),
        PackageV2.objects.from_purl("pkg:pypi/missing@2.0.0"),
    ]
    mock_versions.side_effect = registry_error(404)
    logger = Mock()

    counts = flag_ghost_packages(
        PackageURL(type="pypi", name="missing"), iter(packages), logger=logger
    )

    for package in packages:
        package.refresh_from_db()
        assert package.is_ghost is True
    assert counts.packages == 1
    assert counts.versions == 0
    logger.assert_called_once_with("Flagging ghost package pkg:pypi/missing", level=logging.WARNING)


@pytest.mark.django_db
@patch("vulnerabilities.pipelines.v2_improvers.flag_ghost_packages.versions")
def test_empty_release_list_does_not_mean_missing_package(mock_versions):
    package = PackageV2.objects.from_purl("pkg:pypi/empty@1.0.0")
    mock_versions.return_value = []
    logger = Mock()

    counts = flag_ghost_packages(PackageURL(type="pypi", name="empty"), [package], logger=logger)

    package.refresh_from_db()
    assert package.is_ghost is True
    assert counts.packages == 0
    assert counts.versions == 1
    logger.assert_called_once_with(
        "Flagging ghost package version pkg:pypi/empty@1.0.0 for PurlDB verification",
        level=logging.INFO,
    )


@pytest.mark.django_db
@patch("vulnerabilities.pipelines.v2_improvers.flag_ghost_packages.versions")
def test_unversioned_existing_package_is_not_a_ghost_version(mock_versions):
    package = PackageV2.objects.from_purl("pkg:pypi/empty")
    mock_versions.return_value = []
    logger = Mock()

    counts = flag_ghost_packages(PackageURL(type="pypi", name="empty"), [package], logger=logger)

    package.refresh_from_db()
    assert package.is_ghost is False
    assert counts.packages == counts.versions == 0
    logger.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize("version", ["1.0.0", "v1.0.0", "V1.0.0"])
@patch("vulnerabilities.pipelines.v2_improvers.flag_ghost_packages.versions")
def test_known_version_clears_previous_ghost_flag(mock_versions, version):
    package = PackageV2.objects.from_purl(f"pkg:pypi/real@{version}")
    package.is_ghost = True
    package.save()
    mock_versions.return_value = [PackageVersion(value="v1.0.0")]

    counts = flag_ghost_packages(PackageURL(type="pypi", name="real"), [package])

    package.refresh_from_db()
    assert package.is_ghost is False
    assert counts.packages == counts.versions == 0


@pytest.mark.django_db
@pytest.mark.parametrize("was_ghost", [False, True])
@pytest.mark.parametrize(
    "error", [registry_error(403), registry_error(429), registry_error(500), Timeout()]
)
@patch("vulnerabilities.pipelines.v2_improvers.flag_ghost_packages.versions")
def test_lookup_errors_preserve_existing_flags(mock_versions, error, was_ghost):
    package = PackageV2.objects.from_purl("pkg:pypi/real@1.0.0")
    package.is_ghost = was_ghost
    package.save()
    mock_versions.side_effect = error
    logger = Mock()

    counts = flag_ghost_packages(PackageURL(type="pypi", name="real"), [package], logger=logger)

    package.refresh_from_db()
    assert package.is_ghost is was_ghost
    assert counts.packages == counts.versions == 0
    assert logger.call_args.kwargs["level"] == logging.ERROR


@patch("vulnerabilities.pipelines.v2_improvers.flag_ghost_packages.versions")
def test_partial_version_lookup_404_does_not_report_missing_package(mock_versions):
    def partial_versions():
        yield PackageVersion(value="1.0.0")
        raise registry_error(404)

    mock_versions.return_value = partial_versions()
    logger = Mock()

    assert get_versions(PackageURL(type="pypi", name="real"), logger=logger) is None
    assert logger.call_args.kwargs["level"] == logging.ERROR


@pytest.mark.parametrize("endpoint", ["list", "v1.0.0.info"])
@patch("vulnerabilities.pipelines.v2_improvers.flag_ghost_packages.versions")
def test_go_lookup_404_is_not_proof_of_missing_package(mock_versions, endpoint):
    mock_versions.side_effect = registry_error(
        404, url=f"https://proxy.golang.org/github.com/example/module/@v/{endpoint}"
    )
    logger = Mock()

    purl = PackageURL.from_string("pkg:golang/github.com/example/module")
    assert get_versions(purl, logger=logger) is None
    assert logger.call_args.kwargs["level"] == logging.ERROR
