# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import logging
import tempfile
import textwrap
from pathlib import Path
from urllib.parse import urlparse

import requests
from django.conf import settings
from git import GitCommandError
from git import Repo

logger = logging.getLogger(__name__)


def url_exists(url, timeout=5):
    """
    Check if the given `url` is reachable by doing head request.
    Return True if response status is 200, else False.
    """
    try:
        response = requests.head(url, timeout=timeout)
        response.raise_for_status()
    except requests.exceptions.RequestException as request_exception:
        logger.debug(f"Error while checking {url}: {request_exception}")
        return False

    return response.status_code == requests.codes.ok


def is_configured():
    """Return True if the required FederatedCode settings have been set."""
    if all(
        [
            settings.FEDERATEDCODE_VULNERABILITIES_REPO,
            settings.FEDERATEDCODE_GIT_SERVICE_TOKEN,
            settings.FEDERATEDCODE_GIT_SERVICE_EMAIL,
            settings.FEDERATEDCODE_GIT_SERVICE_NAME,
        ]
    ):
        return True
    return False


def create_federatedcode_working_dir():
    """Create temporary working dir for cloning federatedcode repositories."""
    return Path(tempfile.mkdtemp())


def is_available():
    """Return True if the configured Git repo is available."""
    if not is_configured():
        return False

    return url_exists(settings.FEDERATEDCODE_VULNERABILITIES_REPO)


def check_federatedcode_configured_and_available(logger):
    """
    Check if the criteria for pushing the results to FederatedCode
    is satisfied.

    Criteria:
        - FederatedCode is configured and available.
    """
    if not is_configured():
        raise Exception("FederatedCode is not configured.")

    if not is_available():
        raise Exception("FederatedCode Git account is not available.")

    logger("Federatedcode repositories are configured and available.")


def clone_repository(repo_url, clone_path, logger, shallow_clone=True):
    """Clone repository to clone_path."""
    logger(f"Cloning repository {repo_url}")

    authenticated_repo_url = repo_url.replace(
        "https://",
        f"https://{settings.FEDERATEDCODE_GIT_SERVICE_TOKEN}@",
    )
    clone_args = {
        "url": authenticated_repo_url,
        "to_path": clone_path,
    }
    if shallow_clone:
        clone_args["depth"] = 1

    repo = Repo.clone_from(**clone_args)
    repo.config_writer(config_level="repository").set_value(
        "user", "name", settings.FEDERATEDCODE_GIT_SERVICE_NAME
    ).release()
    repo.config_writer(config_level="repository").set_value(
        "user", "email", settings.FEDERATEDCODE_GIT_SERVICE_EMAIL
    ).release()

    return repo


def get_github_org(url):
    """Return org username from GitHub account URL."""
    github_account_url = urlparse(url)
    path_after_domain = github_account_url.path.lstrip("/")
    org_name = path_after_domain.split("/")[0]
    return org_name


def push_changes(repo, remote_name="origin", branch_name=""):
    """Push changes to remote repository."""
    if not branch_name:
        branch_name = repo.active_branch.name
    repo.git.push(remote_name, branch_name, "--no-verify")


def commit_and_push_changes(
    repo,
    files_to_commit,
    commit_message,
    logger,
    remote_name="origin",
):
    """
    Commit and push changes to remote repository.
    Returns True if changes are successfully pushed, False otherwise.
    """
    try:
        commit_changes(repo, files_to_commit, commit_message)
        push_changes(repo, remote_name)
    except GitCommandError as e:
        if "nothing to commit" in e.stdout.lower():
            logger("Nothing to commit, working tree clean.")
        else:
            logger(f"Error while committing change: {e}")
        return False
    return True


def commit_changes(repo, files_to_commit, commit_message):
    """Commit changes in files to a remote repository."""
    if not files_to_commit:
        return

    repo.index.add(files_to_commit)
    repo.git.commit(
        m=textwrap.dedent(commit_message),
        allow_empty=False,
        no_verify=True,
    )


def commit_message(item_type, commit_count, total_commit_count):
    """Commit message for pushing Package vulnerability."""
    from vulnerablecode import __version__ as VERSION

    author_name = settings.FEDERATEDCODE_GIT_SERVICE_NAME
    author_email = settings.FEDERATEDCODE_GIT_SERVICE_EMAIL

    tool_name = "pkg:github/aboutcode-org/vulnerablecode"

    return f"""\
        Add new {item_type} ({commit_count}/{total_commit_count})

        Tool: {tool_name}@v{VERSION}

        Signed-off-by: {author_name} <{author_email}>
        """
