# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import itertools
import json
import shutil
from datetime import datetime
from operator import attrgetter
from pathlib import Path

from aboutcode.pipeline import LoopProgress
from django.conf import settings
from django.utils import timezone

from aboutcode.federated import DataFederation
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes import export
from vulnerabilities.pipes import federatedcode
from vulnerabilities.utils import load_json


class FederatePackageVulnerabilities(VulnerableCodePipeline):
    """
    Export package vulnerabilities and advisories to FederatedCode.

    - Export all packages and advisories to FederatedCode.
    - On subsequent runs, export incremental updates.
    - Remove `checkpoint.json` file from FederatedCode git repository to
        force a full re-export of all packages and advisories.
    """

    pipeline_id = "federate_vulnerabilities_v2"

    @classmethod
    def steps(cls):
        return (
            cls.check_federatedcode_eligibility,
            cls.create_federatedcode_working_dir,
            cls.fetch_federation_config,
            cls.clone_federation_repository,
            cls.load_checkpoint,
            cls.publish_package_related_advisories,
            cls.publish_advisories,
            cls.save_checkpoint,
            cls.delete_working_dir,
        )

    def check_federatedcode_eligibility(self):
        """Check if FederatedCode is configured."""
        federatedcode.check_federatedcode_configured_and_available(self.log)

    def create_federatedcode_working_dir(self):
        """Create temporary working dir."""
        self.working_path = federatedcode.create_federatedcode_working_dir()

    def fetch_federation_config(self):
        """Fetch config for PackageURL Federation."""
        data_federation = DataFederation.from_url(
            name="aboutcode-data",
            remote_root_url="https://github.com/aboutcode-data",
        )
        self.data_cluster = data_federation.get_cluster("security_advisories")

    def clone_federation_repository(self):
        self.repo = federatedcode.clone_repository(
            repo_url=settings.FEDERATEDCODE_VULNERABILITIES_REPO,
            clone_path=self.working_path / "advisories-data",
            logger=self.log,
        )
        self.repo_path = Path(self.repo.working_dir)

    def load_checkpoint(self):
        checkpoint_file = self.repo_path / "checkpoint.json"
        data = {}
        self.start_time = str(timezone.now())
        self.checkpoint = None
        if checkpoint_file.exists():
            data = load_json(checkpoint_file)

        if last_run := data.get("last_run"):
            self.checkpoint = datetime.fromisoformat(last_run)

    def publish_package_related_advisories(self):
        """Publish package advisories relations to FederatedCode"""
        commit_count = 1
        batch_size = 4000
        chunk_size = 500
        files_to_commit = set()

        packages_count, package_qs = export.package_prefetched_qs(self.checkpoint)
        grouped_packages = itertools.groupby(
            package_qs.iterator(chunk_size=chunk_size),
            key=attrgetter("type", "namespace", "name", "version"),
        )

        self.log(f"Exporting advisory relation for {packages_count} packages.")
        progress = LoopProgress(
            total_iterations=packages_count,
            progress_step=5,
            logger=self.log,
        )
        for _, packages in progress.iter(grouped_packages):
            purl, package_vulnerabilities = export.get_package_related_advisory(packages)
            package_repo, datafile_path = self.data_cluster.get_datafile_repo_and_path(purl)
            package_vulnerability_path = f"packages/{package_repo}/{datafile_path}"

            export.write_file(
                repo_path=self.repo_path,
                file_path=package_vulnerability_path,
                data=package_vulnerabilities,
            )
            files_to_commit.add(package_vulnerability_path)

            if len(files_to_commit) > batch_size:
                if federatedcode.commit_and_push_changes(
                    commit_message=self.commit_message(
                        "Add new package advisory relations",
                        commit_count,
                    ),
                    repo=self.repo,
                    files_to_commit=files_to_commit,
                    logger=self.log,
                ):
                    commit_count += 1
                files_to_commit.clear()

        if files_to_commit:
            federatedcode.commit_and_push_changes(
                commit_message=self.commit_message(
                    "Add new package advisory relations",
                    commit_count,
                    commit_count,
                ),
                repo=self.repo,
                files_to_commit=files_to_commit,
                logger=self.log,
            )

        self.log(f"Federated {packages_count} package advisories.")

    def publish_advisories(self):
        """Publish advisory to FederatedCode"""
        commit_count = 1
        batch_size = 4000
        chunk_size = 1000
        files_to_commit = set()
        advisory_qs = export.advisory_prefetched_qs(self.checkpoint)
        advisory_count = advisory_qs.count()

        self.log(f"Exporting {advisory_count} advisory.")
        progress = LoopProgress(
            total_iterations=advisory_count,
            progress_step=5,
            logger=self.log,
        )
        for advisory in progress.iter(advisory_qs.iterator(chunk_size=chunk_size)):
            advisory_data = export.serialize_advisory(advisory)
            adv_file = f"advisories/{advisory.avid}.yml"
            export.write_file(
                repo_path=self.repo_path,
                file_path=adv_file,
                data=advisory_data,
            )
            files_to_commit.add(adv_file)

            if len(files_to_commit) > batch_size:
                if federatedcode.commit_and_push_changes(
                    commit_message=self.commit_message("Add new advisories", commit_count),
                    repo=self.repo,
                    files_to_commit=files_to_commit,
                    logger=self.log,
                ):
                    commit_count += 1
                files_to_commit.clear()

        if files_to_commit:
            federatedcode.commit_and_push_changes(
                commit_message=self.commit_message(
                    "Add new advisories",
                    commit_count,
                    commit_count,
                ),
                repo=self.repo,
                files_to_commit=files_to_commit,
                logger=self.log,
            )

        self.log(f"Successfully federated {advisory_count} advisories.")

    def save_checkpoint(self):
        checkpoint_file = self.repo_path / "checkpoint.json"
        checkpoint = {"last_run": self.start_time}
        with open(checkpoint_file, "w") as f:
            json.dump(checkpoint, f, indent=2)

        federatedcode.commit_and_push_changes(
            commit_message=self.commit_message("Update checkpoint", 1, 1),
            repo=self.repo,
            files_to_commit=[checkpoint_file],
            logger=self.log,
        )

    def delete_working_dir(self):
        """Remove temporary working dir."""
        if hasattr(self, "working_path") and self.working_path:
            shutil.rmtree(self.working_path)

    def on_failure(self):
        self.delete_working_dir()

    def commit_message(
        self,
        heading,
        commit_count,
        total_commit_count="many",
    ):
        """Commit message for pushing package vulnerability."""
        return federatedcode.commit_message(
            heading=heading,
            commit_count=commit_count,
            total_commit_count=total_commit_count,
        )
