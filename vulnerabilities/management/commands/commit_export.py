#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import os
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests
from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from git import Repo

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = """Commit the exported vulnerability and package in backing git repository"""

    def add_arguments(self, parser):
        parser.add_argument(
            "path",
            help="Path to exported data.",
        )

    def handle(self, *args, **options):
        if path := options["path"]:
            base_path = Path(path)

        if not path or not base_path.is_dir():
            raise CommandError("Enter a valid directory path")

        export_repo_url = os.environ.get("VULNERABLECODE_EXPORT_REPO_URL", None)
        github_service_token = os.environ.get("GITHUB_SERVICE_TOKEN", None)
        github_service_name = os.environ.get("GITHUB_SERVICE_NAME", None)
        github_service_email = os.environ.get("GITHUB_SERVICE_EMAIL", None)

        local_dir = tempfile.mkdtemp()
        current_date = datetime.now().strftime("%Y-%m-%d")

        branch_name = f"export-update-{current_date}"
        commit_message = f"Update package and vulnerability data\nSigned-off-by: {github_service_name} <{github_service_email}>"
        pr_title = "Update package and vulnerability"
        pr_body = ""

        self.stdout.write("Committing vulnerablecode Package and Vulnerability data.")
        repo = self.clone_repository(
            repo_url=export_repo_url,
            local_path=local_dir,
            token=github_service_token,
        )

        repo.config_writer().set_value("user", "name", github_service_name).release()
        repo.config_writer().set_value("user", "email", github_service_email).release()

        self.add_changes(repo=repo, content_path=path)

        if self.commit_and_push_changes(
            repo=repo,
            branch=branch_name,
            commit_message=commit_message,
        ):
            self.create_pull_request(
                repo_url=export_repo_url,
                branch=branch_name,
                title=pr_title,
                body=pr_body,
                token=github_service_token,
            )
        shutil.rmtree(local_dir)

    def clone_repository(self, repo_url, local_path, token):
        """Clone repository to local_path."""
        if os.path.exists(local_path):
            shutil.rmtree(local_path)

        authenticated_repo_url = repo_url.replace("https://", f"https://{token}@")
        return Repo.clone_from(authenticated_repo_url, local_path)

    def add_changes(self, repo, content_path):
        """Copy changes from the ``content_path`` to ``repo``."""

        source_path = Path(content_path)
        destination_path = Path(repo.working_dir)

        for item in source_path.iterdir():
            if not item.is_dir():
                continue
            target_item = destination_path / item.name
            if target_item.exists():
                shutil.rmtree(target_item)
            shutil.copytree(item, target_item)

    def commit_and_push_changes(self, repo, branch, commit_message, remote_name="origin"):
        """Commit changes and push to remote repository, return name of changed files."""

        repo.git.checkout("HEAD", b=branch)
        files_changed = repo.git.diff("HEAD", name_only=True)

        if not files_changed:
            self.stderr.write(self.style.SUCCESS("No changes to commit."))
            return

        repo.git.add(A=True)
        repo.index.commit(commit_message)
        repo.git.push(remote_name, branch)
        return files_changed

    def create_pull_request(self, repo_url, branch, title, body, token):
        """Create a pull request in the GitHub repository."""

        url_parts = urlparse(repo_url).path
        path_parts = url_parts.strip("/").rstrip(".git").split("/")

        if len(path_parts) >= 2:
            repo_owner = path_parts[0]
            repo_name = path_parts[1]
        else:
            raise ValueError("Invalid GitHub repo URL")

        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls"
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
        data = {"title": title, "head": branch, "base": "main", "body": body}

        response = requests.post(url, headers=headers, json=data)

        if response.status_code == 201:
            pr_response = response.json()
            self.stdout.write(
                self.style.SUCCESS(
                    f"Pull request created successfully: {pr_response.get('html_url')}."
                )
            )
        else:
            self.stderr.write(
                self.style.ERROR(f"Failed to create pull request: {response.content}")
            )
