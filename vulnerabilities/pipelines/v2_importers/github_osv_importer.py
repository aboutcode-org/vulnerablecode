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
from typing import Iterable
from urllib.parse import quote

from fetchcode.vcs import fetch_via_vcs
from git import Repo
from git.exc import GitError

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.models import GitImportCheckpoint
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.osv_v2 import parse_advisory_data_v3


class GithubOSVImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    GithubOSV Importer Pipeline

    Collect advisories from the GitHub Advisory Database repository.
    """

    pipeline_id = "github_osv_importer_v2"
    datasource_id = "github_osv"
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://github.com/github/advisory-database/blob/main/LICENSE.md"
    repo_url = "git+https://github.com/github/advisory-database/"

    precedence = 200
    raise_on_import_error = True
    advisory_directory = "advisories/github-reviewed"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.select_advisory_files,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
            cls.save_checkpoint,
        )

    def clone(self):
        self.advisory_files = None
        self.log(f"Cloning {self.repo_url}")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def select_advisory_files(self):
        """Select added and changed JSON files, or use a full scan without usable history."""
        self.advisory_files = None
        checkpoint = GitImportCheckpoint.objects.filter(
            pipeline_id=self.pipeline_id, repo_url=self.repo_url
        ).first()
        with Repo(self.vcs_response.dest_dir) as repo:
            self.current_commit = repo.head.commit.hexsha
            if not checkpoint:
                self.log("No Git import checkpoint; importing all reviewed advisories")
                return

            try:
                previous_commit = repo.commit(checkpoint.commit_hash)
                if not repo.is_ancestor(previous_commit, self.current_commit):
                    self.log("Git import history has diverged; importing all reviewed advisories")
                    return
                changes = repo.git.diff(
                    "--name-status",
                    "-z",
                    "--no-renames",
                    previous_commit.hexsha,
                    self.current_commit,
                    "--",
                    self.advisory_directory,
                ).split("\0")
            except (GitError, ValueError) as error:
                self.log(f"Git import checkpoint unavailable. Importing all advisories: {error}")
                return

        base_path = Path(self.vcs_response.dest_dir)
        files = []
        # --no-renames represents moves as deletion plus addition. NUL separators
        # preserve spaces and newlines in filenames.
        for change_type, relative_path in zip(changes[::2], changes[1::2]):
            if not relative_path.endswith(".json"):
                continue
            if change_type == "D":
                self.log(f"Deleted upstream advisory retained for review: {relative_path}")
            else:
                files.append(base_path / relative_path)
        self.advisory_files = tuple(sorted(files))
        self.log(f"Selected {len(files)} added or changed advisory files")

    def get_advisory_files(self):
        if getattr(self, "advisory_files", None) is None:
            advisory_dir = Path(self.vcs_response.dest_dir) / self.advisory_directory
            self.advisory_files = tuple(sorted(advisory_dir.rglob("*.json")))
        return self.advisory_files

    def advisories_count(self):
        return len(self.get_advisory_files())

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        supported_ecosystems = [
            "pypi",
            "npm",
            "maven",
            # "golang",
            "composer",
            "hex",
            "gem",
            "nuget",
            "cargo",
        ]
        base_path = Path(self.vcs_response.dest_dir)

        for file in self.get_advisory_files():
            advisory_url = "https://github.com/github/advisory-database/blob/main/" + quote(
                file.relative_to(base_path).as_posix()
            )
            with open(file) as f:
                raw_data = json.load(f)
            advisory_text = file.read_text()
            advisory = parse_advisory_data_v3(
                raw_data=raw_data,
                supported_ecosystems=supported_ecosystems,
                advisory_url=advisory_url,
                advisory_text=advisory_text,
            )
            if advisory is None:
                raise ValueError(f"Could not parse advisory: {file}")
            yield advisory

    def save_checkpoint(self):
        """Advance only after every selected advisory and cleanup succeeded."""
        GitImportCheckpoint.objects.update_or_create(
            pipeline_id=self.pipeline_id,
            repo_url=self.repo_url,
            defaults={"commit_hash": self.current_commit},
        )

    def clean_downloads(self):
        if getattr(self, "vcs_response", None):
            self.log("Removing cloned repository")
            self.vcs_response.delete()
            self.vcs_response = None

    def on_failure(self):
        self.clean_downloads()
