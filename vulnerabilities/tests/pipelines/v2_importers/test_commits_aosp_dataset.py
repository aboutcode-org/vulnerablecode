#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from vulnerabilities.pipelines.v2_importers.aosp_importer import AospImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "aosp"


@pytest.mark.django_db
def test_aosp_advisories():
    expected_file = os.path.join(TEST_DATA, "aosp_advisoryv2-expected.json")
    pipeline = AospImporterPipeline()
    pipeline.vcs_response = Mock(dest_dir=TEST_DATA)
    result = [adv.to_dict() for adv in pipeline.collect_advisories()]
    util_tests.check_results_against_json(result, expected_file)
