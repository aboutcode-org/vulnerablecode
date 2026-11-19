#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.

from datetime import datetime
from unittest.mock import patch

import pytest
from django.template.loader import render_to_string
from django.test import RequestFactory
from git import Actor
from git import Repo
from git.exc import GitCommandError

from vulnerabilities.models import AdvisoryReference
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import PackageCommitPatch
from vulnerabilities.models import Patch
from vulnerabilities.pipelines.v2_improvers.reference_collect_commits import (
    CollectReferencesFixCommitsPipeline,
)
from vulnerabilities.pipes.commit_reachability import get_branch_reachability


@pytest.fixture
def local_git_repo(tmp_path):
    """Create branch, tag-only, and dangling commits without any network access."""
    with Repo.init(tmp_path / "source", initial_branch="main") as repo:
        actor = Actor("Reachability Test", "reachability@example.com")

        def commit(message):
            return repo.index.commit(message, author=actor, committer=actor).hexsha

        root = commit("root")
        main = commit("main")
        repo.git.checkout("-b", "security", root)
        security = commit("security branch only")
        repo.git.checkout("--detach", root)
        tagged = commit("tag only")
        repo.create_tag("tagged-fix", tagged)
        dangling = commit("dangling fix")
        repo.git.checkout("main")
        yield repo, {
            "root": root,
            "main": main,
            "security": security,
            "tagged": tagged,
            "dangling": dangling,
        }


@pytest.mark.parametrize(
    "name,expected",
    [
        ("root", "reachable"),
        ("main", "reachable"),
        ("security", "reachable"),
        ("tagged", "unreachable"),
        ("dangling", "unreachable"),
    ],
)
def test_branch_reachability_uses_only_branches(local_git_repo, name, expected):
    repo, commits = local_git_repo
    commit_hash = commits[name]
    assert get_branch_reachability(repo, [commit_hash], all_branches_fetched=True) == {
        commit_hash: expected
    }


def test_branch_reachability_requires_all_branches(local_git_repo, tmp_path):
    source, commits = local_git_repo
    with Repo.clone_from(
        source.working_dir, tmp_path / "single", single_branch=True, branch="main"
    ) as repo:
        assert get_branch_reachability(repo, commits.values()) == dict.fromkeys(
            commits.values(), "unknown"
        )


def test_branch_reachability_shallow_clone_is_unknown(local_git_repo, tmp_path):
    source, commits = local_git_repo
    with Repo.clone_from(
        source.working_dir, tmp_path / "shallow", bare=True, depth=1, no_local=True
    ) as repo:
        assert repo.git.rev_parse("--is-shallow-repository") == "true"
        assert get_branch_reachability(
            repo, commits.values(), all_branches_fetched=True
        ) == dict.fromkeys(commits.values(), "unknown")


def test_branch_reachability_partial_clone_is_unknown(local_git_repo, tmp_path):
    source, commits = local_git_repo
    with Repo.clone_from(
        source.working_dir, tmp_path / "partial", bare=True, filter="blob:none"
    ) as repo:
        with repo.config_reader() as config:
            assert config.get_value('remote "origin"', "promisor") is True
        assert get_branch_reachability(
            repo, commits.values(), all_branches_fetched=True
        ) == dict.fromkeys(commits.values(), "unknown")


def test_branch_reachability_abbreviated_commit(local_git_repo):
    repo, commits = local_git_repo
    abbreviated = commits["security"][:12]
    assert get_branch_reachability(repo, [abbreviated], all_branches_fetched=True) == {
        abbreviated: "reachable"
    }


@pytest.mark.django_db
def test_pipeline_preserves_commits_and_flags_reachability(local_git_repo):
    repo, commits = local_git_repo
    advisory = AdvisoryV2.objects.create(
        advisory_id="CVE-2025-2367",
        datasource_id="test-ds",
        avid="test-ds/CVE-2025-2367",
        url="https://example.com/advisory/CVE-2025-2367",
        unique_content_id="reachability-test",
        date_collected=datetime.now(),
        pipeline_id="test-pipeline",
    )
    vcs_url = repo.working_dir
    references = [
        f"https://github.com/test/testpkg/commit/{commit_hash}" for commit_hash in commits.values()
    ]
    for url in references[:-1]:
        advisory.references.add(AdvisoryReference.objects.create(url=url))
    # Patch references are collected as well as advisory references.
    advisory.patches.add(Patch.objects.create(patch_url=references[-1]))
    pipeline = CollectReferencesFixCommitsPipeline()
    original_get_vcs_data = pipeline.get_vcs_data

    def local_vcs_data(url):
        purl, _, commit_hash = original_get_vcs_data(url)
        return purl, vcs_url, commit_hash

    with patch.object(pipeline, "get_vcs_data", side_effect=local_vcs_data):
        pipeline.collect_and_store_fix_commits()
        pipeline.collect_and_store_fix_commits()

    impact = advisory.impacted_packages.get()
    assert impact.fixed_by_package_commit_patches.count() == len(commits)
    assert set(PackageCommitPatch.objects.values_list("branch_reachability", flat=True)) == {
        "unknown"
    }

    # The repository is cloned once for all commits, and a rerun updates existing rows.
    with patch(
        "vulnerabilities.pipelines.v2_improvers.reference_collect_commits.Repo.clone_from",
        wraps=Repo.clone_from,
    ) as clone:
        pipeline.check_commit_branch_reachability()
        assert clone.call_count == 1

    assert dict(PackageCommitPatch.objects.values_list("commit_hash", "branch_reachability")) == {
        commit_hash: "reachable" if name in ("root", "main", "security") else "unreachable"
        for name, commit_hash in commits.items()
    }
    assert impact.fixed_by_package_commit_patches.count() == len(commits)
    assert any(commits["dangling"] in line for line in pipeline.execution_log)

    # Moving a branch to a previously dangling commit refreshes its flag.
    repo.create_head("reviewed-fix", commits["dangling"])
    pipeline.check_commit_branch_reachability()
    assert set(PackageCommitPatch.objects.values_list("branch_reachability", flat=True)) == {
        "reachable"
    }


@pytest.mark.django_db
def test_pipeline_marks_unavailable_repository_unknown(tmp_path, local_git_repo):
    repo, commits = local_git_repo
    available_commit = PackageCommitPatch.objects.create(
        vcs_url=repo.working_dir, commit_hash=commits["main"]
    )
    commit = PackageCommitPatch.objects.create(
        vcs_url=str(tmp_path / "missing-repository"),
        commit_hash="a" * 40,
        branch_reachability="unreachable",
        patch_text="preserve this patch",
    )
    pipeline = CollectReferencesFixCommitsPipeline()
    pipeline.check_commit_branch_reachability()
    commit.refresh_from_db()
    assert commit.branch_reachability == "unknown"
    assert commit.patch_text == "preserve this patch"
    available_commit.refresh_from_db()
    assert available_commit.branch_reachability == "reachable"
    assert any("Branch reachability unknown" in line for line in pipeline.execution_log)


@pytest.mark.django_db
def test_pipeline_marks_shallow_repository_unknown(local_git_repo, tmp_path):
    source, commits = local_git_repo
    with Repo.clone_from(
        source.working_dir, tmp_path / "shallow-source", bare=True, depth=1, no_local=True
    ) as shallow:
        commit = PackageCommitPatch.objects.create(
            vcs_url=shallow.git_dir, commit_hash=commits["root"]
        )
        CollectReferencesFixCommitsPipeline().check_commit_branch_reachability()
        commit.refresh_from_db()
        assert commit.branch_reachability == "unknown"


@pytest.mark.django_db
def test_pipeline_git_walk_failure_is_unknown(local_git_repo):
    repo, commits = local_git_repo
    commit = PackageCommitPatch.objects.create(
        vcs_url=repo.working_dir, commit_hash=commits["main"]
    )
    with patch(
        "vulnerabilities.pipelines.v2_improvers.reference_collect_commits.get_branch_reachability",
        side_effect=GitCommandError("git rev-list --branches", 128),
    ):
        CollectReferencesFixCommitsPipeline().check_commit_branch_reachability()
    commit.refresh_from_db()
    assert commit.branch_reachability == "unknown"


@pytest.mark.django_db
@pytest.mark.parametrize("status", ["reachable", "unreachable", "unknown"])
def test_advisory_commit_details_display_reachability(status):
    advisory = AdvisoryV2.objects.create(
        advisory_id="CVE-2025-2367",
        datasource_id="test-ds",
        avid="test-ds/CVE-2025-2367",
        url="https://example.com/advisory/CVE-2025-2367",
        unique_content_id="reachability-display",
        date_collected=datetime.now(),
        pipeline_id="test-pipeline",
    )
    impact = ImpactedPackage.objects.create(advisory=advisory, base_purl="pkg:github/test/testpkg")
    commit = PackageCommitPatch.objects.create(
        vcs_url="https://github.com/test/testpkg",
        commit_hash="a" * 40,
        branch_reachability=status,
    )
    impact.fixed_by_package_commit_patches.add(commit)
    impact.introduced_by_package_commit_patches.add(commit)
    html = render_to_string(
        "advisory_package_commit_details.html",
        {"advisoryv2": advisory},
        request=RequestFactory().get("/"),
    )
    assert html.count(commit.get_branch_reachability_display()) == 2
    assert ("is-warning" in html) == (status == "unreachable")


@pytest.mark.django_db
def test_collect_fix_commits_pipeline_creates_entry():
    advisory = AdvisoryV2.objects.create(
        advisory_id="CVE-2025-1000",
        datasource_id="test-ds",
        avid="test-ds/CVE-2025-1000",
        url="https://example.com/advisory/CVE-2025-1000",
        unique_content_id="11111",
        date_collected=datetime.now(),
        pipeline_id="test-pipeline",
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
    assert fix.branch_reachability == "unknown"
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
        pipeline_id="test-pipeline",
    )

    reference = AdvisoryReference.objects.create(
        url="https://github.com/test/testpkg/issues/12"
    )  # invalid reference 1
    advisory.references.add(reference)

    pipeline = CollectReferencesFixCommitsPipeline()
    pipeline.collect_and_store_fix_commits()
    assert PackageCommitPatch.objects.count() == 0
