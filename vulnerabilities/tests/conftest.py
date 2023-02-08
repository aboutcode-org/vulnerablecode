#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest


@pytest.fixture
def no_mkdir(monkeypatch):
    monkeypatch.delattr("os.mkdir")


@pytest.fixture
def no_rmtree(monkeypatch):
    monkeypatch.delattr("shutil.rmtree")


# TODO: Ignore these tests for now but we need to migrate each one of them to the new struture.
# Step 1: Fix importer_yielder: https://github.com/nexB/vulnerablecode/issues/501
# Step 2: Run test for importer only if it is activated (pytestmark = pytest.mark.skipif(...))
# Step 3: Migrate all the tests
collect_ignore = [
    "test_models.py",
    "test_package_managers.py",
    "test_ruby.py",
    "test_rust.py",
    "test_suse_backports.py",
    "test_suse.py",
    "test_upstream.py",
]
