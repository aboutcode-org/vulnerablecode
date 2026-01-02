#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path

import saneyaml

from vulnerabilities.pipelines.v2_importers.suse_score_importer import (
    SUSESeverityScoreImporterPipeline,
)
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "suse_scores_v2"

TEST_YAML_DB = TEST_DATA / "suse-cvss-scores.yaml"


def test_suse_score_advisories():
    pipeline = SUSESeverityScoreImporterPipeline()

    with open(TEST_YAML_DB) as f:
        pipeline.score_data = saneyaml.load(f)

    result = [adv.to_dict() for adv in pipeline.collect_advisories()]

    expected_file = TEST_DATA / "suse-cvss-scores-expected.json"
    util_tests.check_results_against_json(result, expected_file)
