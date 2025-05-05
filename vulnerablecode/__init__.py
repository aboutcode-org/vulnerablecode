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

__version__ = "36.0.0"


PROJECT_DIR = Path(__file__).resolve().parent
ROOT_DIR = PROJECT_DIR.parent


def get_git_describe_from_local_checkout():
    """
    Return the git describe tag from the local checkout.
    This will only provide a result when the codebase is a git clone.
    """
    with suppress(git.GitError):
        return git.Repo(".").git.describe(tags=True, always=True)


def get_short_commit():
    """
    Return the short commit hash from a Git describe string while removing
    any leading "g" character if present.
    """
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
