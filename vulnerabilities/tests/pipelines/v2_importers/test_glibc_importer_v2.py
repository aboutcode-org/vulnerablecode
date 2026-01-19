#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from vulnerabilities.pipelines.v2_importers.glibc_importer import GlibcImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "glibc"

TEST_CVE_FILES = [
    TEST_DATA / "advisories" / "GLIBC-SA-2023-0001",
    TEST_DATA / "advisories" / "GLIBC-SA-2025-0004",
    TEST_DATA / "advisories" / "GLIBC-SA-2026-0002",
]


@pytest.mark.django_db
@pytest.mark.parametrize("glibc_file", TEST_CVE_FILES)
def test_glibc_advisories_per_file(glibc_file):
    pipeline = GlibcImporterPipeline()
    pipeline.vcs_response = Mock(dest_dir=TEST_DATA)

    with patch.object(Path, "rglob", return_value=[glibc_file]):
        result = [adv.to_dict() for adv in pipeline.collect_advisories()]

    expected_file = glibc_file.with_name(glibc_file.stem + "-expected.json")
    util_tests.check_results_against_json(result, expected_file)
