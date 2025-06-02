#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
import sys
from contextlib import suppress
from pathlib import Path

import git

__version__ = "36.1.2"


PROJECT_DIR = Path(__file__).resolve().parent
ROOT_DIR = PROJECT_DIR.parent


def get_git_describe_from_local_checkout():
    """
    Return the git describe tag from the local checkout.
    This will only provide a result when the codebase is a git clone.
    """
    with suppress(git.GitError):
        return git.Repo(".").git.describe(tags=True, always=True)


def get_git_commit_from_version_file():
    """
    Return the git commit from the ".VERSION" file.
    This will only provide a result when the codebase is an extracted git archive.
    """
    version_file = ROOT_DIR / ".VERSION"
    if not version_file.exists():
        return

    try:
        lines = version_file.read_text().splitlines()
        commit_line = lines[1]
        if not commit_line.startswith("commit=") or commit_line.startswith("commit=$Format"):
            return
        return commit_line.replace("commit=", "")
    except (UnicodeDecodeError):
        return


def get_git_tag_from_version_file():
    """Return the tag from the ".VERSION" file."""
    version_file = ROOT_DIR / ".VERSION"
    if not version_file.exists():
        return

    try:
        lines = version_file.read_text().splitlines()
        ref_line = lines[0]
        if "tag:" in ref_line:
            if vcio_tag := ref_line.split("tag:")[-1].strip():
                return vcio_tag
    except (UnicodeDecodeError):
        return


def get_git_tag():
    """Return the tag from the ".VERSION" file or __version__."""
    if vcio_tag := get_git_tag_from_version_file():
        return vcio_tag
    return __version__


def get_short_commit():
    """
    Return the short commit hash from the .VERSION file or from `git describe`
    in a local checkout or docker deployment using a local checkout.
    """
    from vulnerablecode import settings

    if short_commit := get_git_commit_from_version_file():
        return short_commit
    if hasattr(settings, "VULNERABLECODE_GIT_COMMIT"):
        return settings.VULNERABLECODE_GIT_COMMIT
    if git_describe := get_git_describe_from_local_checkout():
        short_commit = git_describe.split("-")[-1]
        return short_commit.lstrip("g")


def command_line():
    """
    Command line entry point.
    """
    from django.core.management import execute_from_command_line

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vulnerablecode.settings")
    execute_from_command_line(sys.argv)
