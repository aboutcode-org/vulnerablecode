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
from univers.versions import Version

from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines.v2_improvers.computer_package_version_rank import (
    ComputeVersionRankPipeline,
)


@pytest.mark.django_db
class TestComputeVersionRankPipeline:
    @pytest.fixture
    def pipeline(self):
        return ComputeVersionRankPipeline()

    @pytest.fixture
    def packages(self, db):
        package_type = "pypi"
        namespace = "test_namespace"
        name = "test_package"
        PackageV2.objects.create(type=package_type, namespace=namespace, name=name, version="1.0.0")
        PackageV2.objects.create(type=package_type, namespace=namespace, name=name, version="1.1.0")
        PackageV2.objects.create(type=package_type, namespace=namespace, name=name, version="0.9.0")
        return PackageV2.objects.filter(type=package_type, namespace=namespace, name=name)

    def test_compute_and_store_version_rank(self, pipeline, packages):
        with patch.object(pipeline, "log") as mock_log:
            pipeline.compute_and_store_version_rank()
            assert mock_log.call_count > 0
            for package in packages:
                assert package.version_rank is not None

    def test_update_version_rank_for_group(self, pipeline, packages):
        with patch.object(PackageV2.objects, "bulk_update") as mock_bulk_update:
            pipeline.update_version_rank_for_group(packages)
            mock_bulk_update.assert_called_once()
            updated_packages = mock_bulk_update.call_args[0][0]
            assert len(updated_packages) == len(packages)
            for idx, package in enumerate(sorted(packages, key=lambda p: Version(p.version))):
                assert updated_packages[idx].version_rank == idx

    def test_sort_packages_by_version(self, pipeline, packages):
        sorted_packages = pipeline.sort_packages_by_version(packages)
        versions = [p.version for p in sorted_packages]
        assert versions == sorted(versions, key=Version)

    def test_sort_packages_by_version_empty(self, pipeline):
        assert pipeline.sort_packages_by_version([]) == []

    def test_sort_packages_by_version_invalid_scheme(self, pipeline, packages):
        for package in packages:
            package.type = "invalid"
        assert pipeline.sort_packages_by_version(packages) == []

    def test_compute_and_store_version_rank_invalid_scheme(self, pipeline):
        PackageV2.objects.create(type="invalid", namespace="test", name="package", version="1.0.0")
        with patch.object(pipeline, "log") as mock_log:
            pipeline.compute_and_store_version_rank()
            mock_log.assert_any_call("Successfully populated `version_rank` for all packages.")
