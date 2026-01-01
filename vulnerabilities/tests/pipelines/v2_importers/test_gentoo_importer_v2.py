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

from vulnerabilities.pipelines.v2_importers.gentoo_importer import GentooImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "gentoo_v2"

TEST_CVE_FILES = [
    TEST_DATA / "glsa-201709-09.xml",
    TEST_DATA / "glsa-202511-02.xml",
    TEST_DATA / "glsa-202512-01.xml",
]


@pytest.mark.django_db
@pytest.mark.parametrize("xml_file", TEST_CVE_FILES)
def test_gentoo_advisories_per_file(xml_file):
    pipeline = GentooImporterPipeline()
    pipeline.vcs_response = Mock(dest_dir=TEST_DATA)

    with patch.object(Path, "glob", return_value=[xml_file]):
        result = [adv.to_dict() for adv in pipeline.collect_advisories()]

    expected_file = xml_file.with_name(xml_file.stem + "-expected.json")
    util_tests.check_results_against_json(result, expected_file)
