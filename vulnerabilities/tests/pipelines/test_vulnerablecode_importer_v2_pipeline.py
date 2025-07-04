#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from datetime import datetime
from datetime import timedelta
from unittest import mock

import pytest
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import UnMergeablePackageError
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2


class DummyImporter(VulnerableCodeBaseImporterPipelineV2):
    pipeline_id = "dummy"
    log_messages = []

    def log(self, message, level=logging.INFO):
        self.log_messages.append((level, message))

    def collect_advisories(self):
        yield from self._advisories

    def advisories_count(self):
        return len(self._advisories)


@pytest.fixture
def dummy_advisory():
    return AdvisoryData(
        summary="Test advisory",
        aliases=["CVE-2025-0001"],
        references_v2=[],
        severities=[],
        weaknesses=[],
        affected_packages=[],
        advisory_id="ADV-123",
        date_published=datetime.now() - timedelta(days=10),
        url="https://example.com/advisory/1",
    )


@pytest.fixture
def dummy_importer(dummy_advisory):
    importer = DummyImporter()
    importer._advisories = [dummy_advisory]
    return importer


@pytest.mark.django_db
def test_collect_and_store_advisories(dummy_importer):
    dummy_importer.collect_and_store_advisories()
    assert len(dummy_importer.log_messages) >= 2
    assert "Successfully collected" in dummy_importer.log_messages[-1][1]
    assert AdvisoryV2.objects.count() == 1


def test_get_advisory_packages_basic(dummy_importer):
    purl = PackageURL("pypi", None, "dummy", "1.0.0")
    affected_package = mock.Mock()
    affected_package.package = purl
    dummy_importer.unfurl_version_ranges = False

    with mock.patch(
        "vulnerabilities.improvers.default.get_exact_purls", return_value=([purl], [purl])
    ):
        with mock.patch.object(
            PackageV2.objects, "get_or_create_from_purl", return_value=(mock.Mock(), True)
        ) as mock_get:
            dummy_importer.get_advisory_packages(
                advisory_data=mock.Mock(affected_packages=[affected_package])
            )
            assert mock_get.call_count == 2  # one affected, one fixed


def test_get_published_package_versions_filters(dummy_importer):
    purl = PackageURL("pypi", None, "example", None)

    dummy_versions = [
        mock.Mock(value="1.0.0", release_date=datetime.now() - timedelta(days=5)),
        mock.Mock(value="2.0.0", release_date=datetime.now() + timedelta(days=5)),  # future
    ]

    with mock.patch(
        "vulnerabilities.pipelines.package_versions.versions", return_value=dummy_versions
    ):
        versions = dummy_importer.get_published_package_versions(purl, until=datetime.now())
        assert "1.0.0" in versions
        assert "2.0.0" not in versions


def test_get_published_package_versions_failure_logs(dummy_importer):
    purl = PackageURL("pypi", None, "example", None)
    with mock.patch(
        "vulnerabilities.pipelines.package_versions.versions", side_effect=Exception("fail")
    ):
        versions = dummy_importer.get_published_package_versions(purl)
        assert versions == []
        assert any("Failed to fetch versions" in msg for lvl, msg in dummy_importer.log_messages)


def test_expand_version_range_to_purls(dummy_importer):
    purls = list(
        dummy_importer.expand_verion_range_to_purls("npm", "lodash", "lodash", ["1.0.0", "1.1.0"])
    )
    assert all(isinstance(p, PackageURL) for p in purls)
    assert purls[0].name == "lodash"


def test_resolve_package_versions(dummy_importer):
    dummy_importer.ignorable_versions = []
    dummy_importer.expand_verion_range_to_purls = lambda *args, **kwargs: [
        PackageURL("npm", None, "a", "1.0.0")
    ]

    with mock.patch(
        "vulnerabilities.pipelines.resolve_version_range", return_value=(["1.0.0"], ["1.1.0"])
    ), mock.patch(
        "vulnerabilities.pipelines.get_affected_packages_by_patched_package",
        return_value={None: [PackageURL("npm", None, "a", "1.0.0")]},
    ), mock.patch(
        "vulnerabilities.pipelines.nearest_patched_package", return_value=[]
    ):
        aff, fix = dummy_importer.resolve_package_versions(
            affected_version_range=">=1.0.0",
            pkg_type="npm",
            pkg_namespace=None,
            pkg_name="a",
            valid_versions=["1.0.0", "1.1.0"],
        )
        assert any(isinstance(p, PackageURL) for p in aff)


def test_get_impacted_packages_mergeable(dummy_importer):
    ap = mock.Mock()
    ap.package = PackageURL("npm", None, "abc", None)
    dummy_importer.get_published_package_versions = lambda package_url, until: ["1.0.0", "1.1.0"]
    dummy_importer.resolve_package_versions = lambda **kwargs: (
        [PackageURL("npm", None, "abc", "1.0.0")],
        [PackageURL("npm", None, "abc", "1.1.0")],
    )

    with mock.patch(
        "vulnerabilities.importer.AffectedPackage.merge",
        return_value=(ap.package, [">=1.0.0"], ["1.1.0"]),
    ):
        aff, fix = dummy_importer.get_impacted_packages([ap], datetime.now())
        assert len(aff) == 1 and aff[0].version == "1.0.0"
        assert len(fix) == 1 and fix[0].version == "1.1.0"


def test_get_impacted_packages_unmergeable(dummy_importer):
    ap = mock.Mock()
    ap.package = PackageURL("npm", None, "abc", None)
    ap.affected_version_range = ">=1.0.0"
    ap.fixed_version = None

    dummy_importer.get_published_package_versions = lambda package_url, until: ["1.0.0", "1.1.0"]
    dummy_importer.resolve_package_versions = lambda **kwargs: (
        [PackageURL("npm", None, "abc", "1.0.0")],
        [PackageURL("npm", None, "abc", "1.1.0")],
    )

    with mock.patch(
        "vulnerabilities.importer.AffectedPackage.merge", side_effect=UnMergeablePackageError
    ):
        aff, fix = dummy_importer.get_impacted_packages([ap], datetime.utcnow())
        assert len(aff) == 1
        assert aff[0].version == "1.0.0"
