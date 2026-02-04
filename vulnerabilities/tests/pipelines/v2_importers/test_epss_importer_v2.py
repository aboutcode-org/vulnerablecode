#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path

import pytest

from vulnerabilities.pipelines.v2_importers.epss_importer_v2 import EPSSImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "epss"

TEST_CVE_FILES = (TEST_DATA / "epss_scores-2025-x-x.csv",)


@pytest.mark.django_db
@pytest.mark.parametrize("csv_file", TEST_CVE_FILES)
def test_epss_advisories_per_file(csv_file):
    pipeline = EPSSImporterPipeline()

    with open(csv_file, "r") as f:
        pipeline.lines = f.readlines()

    result = [adv.to_dict() for adv in pipeline.collect_advisories()]
    expected_file = Path(TEST_DATA / "epss-expected.json")
    util_tests.check_results_against_json(result, expected_file)
