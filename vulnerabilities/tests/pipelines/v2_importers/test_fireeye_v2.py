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

from vulnerabilities.pipelines.v2_importers.fireeye_importer_v2 import FireeyeImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "fireeye_v2"

TEST_CVE_FILES = [
    TEST_DATA / "FEYE-2019-0002.md",
    TEST_DATA / "FEYE-2020-0020.md",
    TEST_DATA / "MNDT-2025-0009.md",
]


@pytest.mark.django_db
@pytest.mark.parametrize("md_file", TEST_CVE_FILES)
def test_fireeye_advisories_per_file(md_file):
    pipeline = FireeyeImporterPipeline()
    pipeline.vcs_response = Mock(dest_dir=TEST_DATA)

    with patch.object(Path, "glob", return_value=[md_file]):
        result = [adv.to_dict() for adv in pipeline.collect_advisories()]

    expected_file = md_file.with_name(md_file.stem + "-expected.json")
    util_tests.check_results_against_json(result, expected_file)
