#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.

from datetime import datetime

import pytest

from vulnerabilities.models import AdvisoryReference
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import PackageCommitPatch
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines.v2_improvers.reference_collect_commits import (
    CollectReferencesFixCommitsPipeline,
)


@pytest.mark.django_db
def test_collect_fix_commits_pipeline_creates_entry():
    advisory = AdvisoryV2.objects.create(
        advisory_id="CVE-2025-1000",
        datasource_id="test-ds",
        avid="test-ds/CVE-2025-1000",
        url="https://example.com/advisory/CVE-2025-1000",
        unique_content_id="11111",
        date_collected=datetime.now(),
    )

    reference = AdvisoryReference.objects.create(
        url="https://github.com/test/testpkg/commit/6bd301819f8f69331a55ae2336c8b111fc933f3d"
    )
    advisory.references.add(reference)

    pipeline = CollectReferencesFixCommitsPipeline()
    pipeline.collect_and_store_fix_commits()

    package_commit_patch = PackageCommitPatch.objects.all()
    impacted_packages = advisory.impacted_packages.all()

    assert package_commit_patch.count() == 1
    assert impacted_packages.count() == 1

    fix = package_commit_patch.first()
    assert fix.commit_hash == "6bd301819f8f69331a55ae2336c8b111fc933f3d"
    assert fix.vcs_url == "https://github.com/test/testpkg"
    assert impacted_packages.first().fixed_by_package_commit_patches.count() == 1


@pytest.mark.django_db
def test_collect_fix_commits_pipeline_skips_non_commit_urls():
    advisory = AdvisoryV2.objects.create(
        advisory_id="CVE-2025-2000",
        datasource_id="test-ds",
        avid="test-ds/CVE-2025-2000",
        url="https://example.com/advisory/CVE-2025-2000",
        unique_content_id="11111",
        date_collected=datetime.now(),
    )

    reference = AdvisoryReference.objects.create(
        url="https://github.com/test/testpkg/issues/12"
    )  # invalid reference 1
    advisory.references.add(reference)

    pipeline = CollectReferencesFixCommitsPipeline()
    pipeline.collect_and_store_fix_commits()
    assert PackageCommitPatch.objects.count() == 0
