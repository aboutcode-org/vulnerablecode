#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
#

from pathlib import Path
from unittest import mock

import saneyaml
from packageurl import PackageURL

from vulnerabilities.pipelines.v2_importers.gitlab_live_importer import GitLabLiveImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "gitlab"


@mock.patch(
    "vulnerabilities.pipelines.v2_importers.gitlab_live_importer.fetch_gitlab_advisories_for_purl"
)
def test_gitlab_importer_package_first_mode_found_with_version(mock_fetch):
    pkg_type = "pypi"
    response_file = TEST_DATA / f"{pkg_type}.yaml"
    expected_file = TEST_DATA / f"{pkg_type}-live-importer-expected.json"

    with open(response_file) as f:
        advisory_dict = saneyaml.load(f)

    mock_fetch.return_value = [advisory_dict]
    purl = PackageURL(type="pypi", name="flask", version="0.9")
    pipeline = GitLabLiveImporterPipeline(purl=purl)
    pipeline.get_purl_inputs()
    advisories = list(pipeline.collect_advisories())
    util_tests.check_results_against_json(advisories[0].to_dict(), expected_file)


@mock.patch(
    "vulnerabilities.pipelines.v2_importers.gitlab_live_importer.fetch_gitlab_advisories_for_purl"
)
def test_gitlab_importer_package_first_mode_none_found(mock_fetch):
    mock_fetch.return_value = []
    purl = PackageURL(type="pypi", name="flask", version="1.2")
    pipeline = GitLabLiveImporterPipeline(purl=purl)
    pipeline.get_purl_inputs()
    advisories = list(pipeline.collect_advisories())
    assert advisories == []
