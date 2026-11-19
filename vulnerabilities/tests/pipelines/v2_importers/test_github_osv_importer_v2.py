#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from fetchcode.vcs import VCSResponse
from git import Actor
from git import Repo

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import GitImportCheckpoint
from vulnerabilities.pipelines.v2_importers.github_osv_importer import GithubOSVImporterPipeline
from vulnerabilities.pipes.advisory import insert_advisory_v2
from vulnerabilities.pipes.osv_v2 import parse_advisory_data_v3

CHANGED_ID = "GHSA-aaaa-bbbb-cccc"
DELETED_ID = "GHSA-dddd-eeee-ffff"
UNCHANGED_ID = "GHSA-gggg-hhhh-jjjj"
ADDED_ID = "GHSA-kkkk-mmmm-nnnn"


@pytest.fixture
def local_osv_repository(tmp_path):
    """A real Git history containing reviewed advisories and unrelated files."""
    with Repo.init(tmp_path / "source", initial_branch="main") as repo:
        actor = Actor("OSV Import Test", "osv-import@example.com")

        def write_advisory(advisory_id, summary="Initial summary", relative_path=None):
            relative_path = relative_path or (
                f"advisories/github-reviewed/2026/{advisory_id}/{advisory_id}.json"
            )
            file = Path(repo.working_dir) / relative_path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(json.dumps({"id": advisory_id, "summary": summary, "affected": []}))
            return file

        def commit(message):
            repo.git.add("--all")
            return repo.index.commit(message, author=actor, committer=actor).hexsha

        for advisory_id in (CHANGED_ID, DELETED_ID, UNCHANGED_ID):
            write_advisory(advisory_id)
        write_advisory("GHSA-pppp-qqqq-rrrr", relative_path="advisories/unreviewed/ignored.json")
        (Path(repo.working_dir) / "README.md").write_text("Not an advisory")
        initial_commit = commit("Initial advisories")
        yield repo, write_advisory, commit, initial_commit


@pytest.fixture
def local_importer_factory(monkeypatch, tmp_path, local_osv_repository):
    repo, _, _, _ = local_osv_repository
    clone_paths = []
    repo_url = "git+" + Path(repo.working_dir).as_uri()

    def make_importer(**clone_options):
        def fetch_local_repository(url):
            assert url == repo_url
            clone_path = tmp_path / f"checkout-{len(clone_paths)}"
            clone_paths.append(clone_path)
            with Repo.clone_from(repo.working_dir, clone_path, no_local=True, **clone_options):
                pass
            return VCSResponse(dest_dir=str(clone_path), vcs_type="git", domain="")

        monkeypatch.setattr(
            "vulnerabilities.pipelines.v2_importers.github_osv_importer.fetch_via_vcs",
            fetch_local_repository,
        )
        importer = GithubOSVImporterPipeline()
        importer.repo_url = repo_url
        return importer

    return make_importer, clone_paths


def checkpoint_for(importer):
    return GitImportCheckpoint.objects.get(
        pipeline_id=importer.pipeline_id, repo_url=importer.repo_url
    )


@pytest.mark.django_db
def test_first_import_reads_all_reviewed_advisories(local_importer_factory, local_osv_repository):
    make_importer, clone_paths = local_importer_factory
    _, _, _, initial_commit = local_osv_repository
    importer = make_importer()

    assert importer.execute() == (0, "")

    assert set(AdvisoryV2.objects.values_list("advisory_id", flat=True)) == {
        CHANGED_ID,
        DELETED_ID,
        UNCHANGED_ID,
    }
    assert checkpoint_for(importer).commit_hash == initial_commit
    assert importer.advisories_count() == 3
    assert all(not path.exists() for path in clone_paths)


@pytest.mark.django_db
def test_incremental_import_adds_updates_and_reports_deletions(
    local_importer_factory, local_osv_repository
):
    make_importer, _ = local_importer_factory
    repo, write_advisory, commit, _ = local_osv_repository
    assert make_importer().execute() == (0, "")
    write_advisory(CHANGED_ID, "Updated summary")
    write_advisory(ADDED_ID)
    write_advisory(DELETED_ID).unlink()
    (Path(repo.working_dir) / "README.md").write_text("Updated documentation")
    write_advisory("GHSA-pppp-qqqq-rrrr", relative_path="advisories/unreviewed/new.json")
    new_commit = commit("Add, update, and delete advisories")

    importer = make_importer()
    with patch(
        "vulnerabilities.pipelines.v2_importers.github_osv_importer.parse_advisory_data_v3",
        wraps=parse_advisory_data_v3,
    ) as parse:
        assert importer.execute() == (0, "")

    assert {call.kwargs["raw_data"]["id"] for call in parse.call_args_list} == {
        CHANGED_ID,
        ADDED_ID,
    }
    assert importer.advisories_count() == 2
    assert checkpoint_for(importer).commit_hash == new_commit
    latest = AdvisoryV2.objects.latest_for_avid(f"github_osv/{CHANGED_ID}")
    assert latest.summary == "Updated summary"
    assert AdvisoryV2.objects.filter(advisory_id=CHANGED_ID).count() == 2
    assert AdvisoryV2.objects.filter(advisory_id=UNCHANGED_ID).count() == 1
    assert AdvisoryV2.objects.filter(advisory_id=ADDED_ID).count() == 1
    assert AdvisoryV2.objects.filter(advisory_id=DELETED_ID, is_latest=True).exists()
    assert any(
        "Deleted upstream advisory retained for review" in log for log in importer.execution_log
    )


@pytest.mark.django_db
def test_unchanged_repository_parses_no_advisories(local_importer_factory):
    make_importer, _ = local_importer_factory
    assert make_importer().execute() == (0, "")
    importer = make_importer()
    with patch(
        "vulnerabilities.pipelines.v2_importers.github_osv_importer.parse_advisory_data_v3"
    ) as parse:
        assert importer.execute() == (0, "")
    parse.assert_not_called()
    assert importer.advisories_count() == 0
    assert AdvisoryV2.objects.count() == 3


@pytest.mark.django_db
def test_deletion_only_run_retains_advisory_and_saves_checkpoint(
    local_importer_factory, local_osv_repository
):
    make_importer, _ = local_importer_factory
    _, write_advisory, commit, _ = local_osv_repository
    assert make_importer().execute() == (0, "")
    write_advisory(DELETED_ID).unlink()
    new_commit = commit("Delete one advisory")
    importer = make_importer()

    with patch(
        "vulnerabilities.pipelines.v2_importers.github_osv_importer.parse_advisory_data_v3"
    ) as parse:
        assert importer.execute() == (0, "")

    parse.assert_not_called()
    assert importer.advisories_count() == 0
    assert AdvisoryV2.objects.filter(advisory_id=DELETED_ID, is_latest=True).exists()
    assert checkpoint_for(importer).commit_hash == new_commit


@pytest.mark.django_db
def test_missing_previous_commit_falls_back_to_full_import(local_importer_factory):
    make_importer, _ = local_importer_factory
    importer = make_importer()
    assert importer.execute() == (0, "")
    GitImportCheckpoint.objects.update(commit_hash="f" * 40)
    importer = make_importer()

    assert importer.execute() == (0, "")

    assert importer.advisories_count() == 3
    assert AdvisoryV2.objects.count() == 3
    assert checkpoint_for(importer).commit_hash == importer.current_commit
    assert any("checkpoint unavailable" in log for log in importer.execution_log)


@pytest.mark.django_db
def test_shallow_history_falls_back_to_full_import(local_importer_factory, local_osv_repository):
    make_importer, _ = local_importer_factory
    _, write_advisory, commit, _ = local_osv_repository
    assert make_importer().execute() == (0, "")
    write_advisory(ADDED_ID)
    commit("Add advisory outside shallow history")
    importer = make_importer(depth=1)

    assert importer.execute() == (0, "")

    assert importer.advisories_count() == 4
    assert AdvisoryV2.objects.count() == 4
    assert checkpoint_for(importer).commit_hash == importer.current_commit


@pytest.mark.django_db
def test_rewritten_history_falls_back_to_full_import(local_importer_factory, local_osv_repository):
    make_importer, _ = local_importer_factory
    repo, write_advisory, commit, _ = local_osv_repository
    assert make_importer().execute() == (0, "")
    repo.git.checkout("--orphan", "rewritten")
    write_advisory(ADDED_ID)
    commit("Replace repository history")
    importer = make_importer()

    assert importer.execute() == (0, "")

    assert importer.advisories_count() == 4
    assert any("history has diverged" in log for log in importer.execution_log)
    assert checkpoint_for(importer).commit_hash == importer.current_commit


@pytest.mark.django_db
def test_renamed_advisory_is_imported_from_new_path(local_importer_factory, local_osv_repository):
    make_importer, _ = local_importer_factory
    _, write_advisory, commit, _ = local_osv_repository
    assert make_importer().execute() == (0, "")
    old_file = write_advisory(CHANGED_ID)
    new_file = old_file.parent / "renamed advisory\nfile.json"
    old_file.rename(new_file)
    commit("Move advisory to a new filename")
    importer = make_importer()

    assert importer.execute() == (0, "")

    assert importer.advisories_count() == 1
    assert importer.advisory_files[0].name == new_file.name
    assert AdvisoryV2.objects.latest_for_avid(f"github_osv/{CHANGED_ID}").url.endswith(
        "renamed%20advisory%0Afile.json"
    )


@pytest.mark.django_db
def test_failed_storage_keeps_checkpoint_and_retries(local_importer_factory, local_osv_repository):
    make_importer, clone_paths = local_importer_factory
    _, write_advisory, commit, initial_commit = local_osv_repository
    assert make_importer().execute() == (0, "")
    write_advisory(CHANGED_ID, "Updated summary")
    write_advisory(ADDED_ID)
    new_commit = commit("Two advisories, one import will fail")

    def fail_one_advisory(**kwargs):
        if kwargs["advisory"].advisory_id == ADDED_ID:
            raise RuntimeError("Cannot store advisory")
        return insert_advisory_v2(**kwargs)

    importer = make_importer()
    with patch("vulnerabilities.pipelines.insert_advisory_v2", side_effect=fail_one_advisory):
        exitcode, error = importer.execute()
    assert exitcode == 1
    assert "Cannot store advisory" in error
    assert checkpoint_for(importer).commit_hash == initial_commit
    assert not AdvisoryV2.objects.filter(advisory_id=ADDED_ID).exists()
    assert AdvisoryV2.objects.filter(advisory_id=CHANGED_ID).count() == 2
    assert all(not path.exists() for path in clone_paths)

    retry = make_importer()
    assert retry.execute() == (0, "")
    assert checkpoint_for(retry).commit_hash == new_commit
    assert AdvisoryV2.objects.filter(advisory_id=ADDED_ID).count() == 1
    assert AdvisoryV2.objects.filter(advisory_id=CHANGED_ID).count() == 2


@pytest.mark.django_db
def test_clone_failure_keeps_checkpoint(local_importer_factory, local_osv_repository):
    make_importer, _ = local_importer_factory
    _, _, _, initial_commit = local_osv_repository
    assert make_importer().execute() == (0, "")
    importer = make_importer()

    with patch(
        "vulnerabilities.pipelines.v2_importers.github_osv_importer.fetch_via_vcs",
        side_effect=OSError("Repository unavailable"),
    ):
        exitcode, error = importer.execute()

    assert exitcode == 1
    assert "Repository unavailable" in error
    assert checkpoint_for(importer).commit_hash == initial_commit


@pytest.mark.django_db
def test_cleanup_failure_keeps_checkpoint(local_importer_factory, local_osv_repository):
    make_importer, clone_paths = local_importer_factory
    _, write_advisory, commit, initial_commit = local_osv_repository
    assert make_importer().execute() == (0, "")
    write_advisory(ADDED_ID)
    commit("Add advisory before cleanup failure")
    importer = make_importer()
    delete = VCSResponse.delete
    attempts = 0

    def fail_first_cleanup(response):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError("Cleanup failed")
        delete(response)

    with patch.object(VCSResponse, "delete", autospec=True, side_effect=fail_first_cleanup):
        exitcode, error = importer.execute()

    assert exitcode == 1
    assert "Cleanup failed" in error
    assert checkpoint_for(importer).commit_hash == initial_commit
    assert all(not path.exists() for path in clone_paths)


@pytest.mark.django_db
@pytest.mark.parametrize("invalid_content", ["{invalid json", "{}"])
def test_parse_failure_does_not_create_checkpoint(
    local_importer_factory, local_osv_repository, invalid_content
):
    make_importer, clone_paths = local_importer_factory
    _, write_advisory, commit, _ = local_osv_repository
    write_advisory(CHANGED_ID).write_text(invalid_content)
    commit("Malformed advisory")
    importer = make_importer()

    exitcode, _ = importer.execute()

    assert exitcode == 1
    assert not GitImportCheckpoint.objects.exists()
    assert all(not path.exists() for path in clone_paths)


@pytest.mark.django_db
def test_checkpoints_are_scoped_to_pipeline_and_repository(local_importer_factory):
    make_importer, _ = local_importer_factory
    GitImportCheckpoint.objects.create(
        pipeline_id=GithubOSVImporterPipeline.pipeline_id,
        repo_url="git+https://example.com/other-repository",
        commit_hash="a" * 40,
    )
    importer = make_importer()
    GitImportCheckpoint.objects.create(
        pipeline_id="another_pipeline",
        repo_url=importer.repo_url,
        commit_hash="b" * 40,
    )

    assert importer.execute() == (0, "")

    assert importer.advisories_count() == 3
    assert GitImportCheckpoint.objects.count() == 3


@pytest.fixture
def sample_osv_advisory(tmp_path: Path):
    advisory_data = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "Sample summary",
        "details": "Sample details",
        "aliases": ["CVE-2021-99999"],
        "affected": [
            {
                "package": {"name": "sample", "ecosystem": "pypi"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]}
                ],
                "versions": ["1.0.0", "1.1.0"],
            }
        ],
        "database_specific": {"cwe_ids": ["CWE-79"]},
    }

    advisory_dir = tmp_path / "advisories/github-reviewed/sample_project"
    advisory_dir.mkdir(parents=True)

    advisory_file = advisory_dir / "GHSA-xxxx-yyyy-zzzz.json"
    advisory_file.write_text(json.dumps(advisory_data, indent=2))

    return tmp_path, advisory_file.read_text(), advisory_data


def test_collect_advisories_from_github_osv(monkeypatch, sample_osv_advisory):
    tmp_path, advisory_text, advisory_json = sample_osv_advisory

    class DummyVCSResponse:
        dest_dir = str(tmp_path)

        def delete(self):
            pass

    importer = GithubOSVImporterPipeline()
    importer.vcs_response = DummyVCSResponse()

    advisories = list(importer.collect_advisories())
    assert len(advisories) == 1

    advisory = advisories[0]
    assert isinstance(advisory, AdvisoryDataV2)
    assert advisory.advisory_id == "GHSA-xxxx-yyyy-zzzz"
    assert "CVE-2021-99999" in advisory.aliases
    assert advisory.summary.startswith("Sample")
    assert advisory.original_advisory_text.strip().startswith("{")
    assert advisory.affected_packages
    assert advisory.affected_packages[0].package.type == "pypi"
