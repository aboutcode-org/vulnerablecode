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
from vulnerabilities.models import CodeFixV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines.v2_improvers.collect_commits import CollectFixCommitsPipeline
from vulnerabilities.pipelines.v2_improvers.collect_commits import is_vcs_url
from vulnerabilities.pipelines.v2_improvers.collect_commits import is_vcs_url_already_processed
from vulnerabilities.pipelines.v2_improvers.collect_commits import normalize_vcs_url


@pytest.mark.parametrize(
    "url,expected",
    [
        ("git://github.com/angular/di.js.git", True),
        ("github:user/repo", True),
        ("user/repo", True),
        ("https://github.com/user/repo.git", True),
        ("git@github.com:user/repo.git", True),
        ("ftp://example.com/not-a-repo", False),
        ("random-string", False),
        ("https://example.com/not-a-repo", False),
    ],
)
def test_is_vcs_url(url, expected):
    assert is_vcs_url(url) is expected


@pytest.mark.parametrize(
    "url,normalized",
    [
        ("git@github.com:user/repo.git", "https://github.com/user/repo.git"),
        ("github:user/repo", "https://github.com/user/repo"),
        ("bitbucket:example/repo", "https://bitbucket.org/example/repo"),
        ("user/repo", "https://github.com/user/repo"),
        ("https://gitlab.com/foo/bar.git", "https://gitlab.com/foo/bar.git"),
    ],
)
def test_normalize_vcs_url(url, normalized):
    assert normalize_vcs_url(url) == normalized


@pytest.mark.django_db
def test_is_vcs_url_already_processed_true():
    advisory = AdvisoryV2.objects.create(
        advisory_id="CVE-2025-9999",
        datasource_id="test-ds",
        avid="test-ds/CVE-2025-9999",
        url="https://example.com/advisory/CVE-2025-9999",
        unique_content_id="11111",
        date_collected=datetime.now(),
    )
    package = PackageV2.objects.create(
        type="bar",
        name="foo",
        version="1.0",
    )
    impact = ImpactedPackage.objects.create(advisory=advisory)
    impact.affecting_packages.add(package)
    CodeFixV2.objects.create(
        commits=["https://github.com/user/repo/commit/abc123"],
        advisory=advisory,
        affected_package=package,
    )
    assert is_vcs_url_already_processed("https://github.com/user/repo/commit/abc123") is True


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
    package = PackageV2.objects.create(
        type="foo",
        name="testpkg",
        version="1.0",
    )
    reference = AdvisoryReference.objects.create(
        url="https://github.com/test/testpkg/commit/abc123"
    )
    impact = ImpactedPackage.objects.create(advisory=advisory)
    impact.affecting_packages.add(package)
    advisory.references.add(reference)

    pipeline = CollectFixCommitsPipeline()
    pipeline.collect_and_store_fix_commits()

    codefixes = CodeFixV2.objects.all()
    assert codefixes.count() == 1
    fix = codefixes.first()
    assert "abc123" in fix.commits[0]
    assert fix.advisory == advisory
    assert fix.affected_package == package


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
    package = PackageV2.objects.create(
        type="pypi",
        name="otherpkg",
        version="2.0",
    )
    impact = ImpactedPackage.objects.create(advisory=advisory)
    impact.affecting_packages.add(package)

    reference = AdvisoryReference.objects.create(url="https://github.com/test/testpkg/issues/12")
    advisory.references.add(reference)

    pipeline = CollectFixCommitsPipeline()
    pipeline.collect_and_store_fix_commits()

    assert CodeFixV2.objects.count() == 0
