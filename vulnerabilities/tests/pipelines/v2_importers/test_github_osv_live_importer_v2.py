import json
from pathlib import Path
from unittest import mock

import pytest
from packageurl import PackageURL

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines.v2_importers.github_osv_live_importer import (
    GithubOSVLiveImporterPipeline,
)
from vulnerabilities.pipelines.v2_importers.github_osv_live_importer import (
    build_github_repo_advisory_url,
)
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "live_github_osv"


@pytest.mark.django_db
@mock.patch("vulnerabilities.pipelines.v2_importers.github_osv_live_importer.fetch_response")
@mock.patch("vulnerabilities.pipelines.v2_importers.github_osv_live_importer.requests.post")
def test_github_osv_live_importer(mocker_osv, mock_github_osv):
    purl = PackageURL(type="pypi", name="django", version="1.4.2")

    mocker_osv.return_value.status_code = 200
    osv_api_path = TEST_DATA / "fetch_osv_api.json"
    with open(osv_api_path, encoding="utf-8") as f:
        mocker_osv.return_value.json.return_value = json.load(f)

    github_osv_path = TEST_DATA / "fetch_github_osv.json"
    with open(github_osv_path, encoding="utf-8") as f:
        raw_advisory_list = json.load(f)

    mock_github_osv.side_effect = lambda url: mock.Mock(
        content=json.dumps(next(adv for adv in raw_advisory_list if adv.get("id") in url))
    )

    pipeline = GithubOSVLiveImporterPipeline(purl=purl)
    pipeline.execute()

    expected_file = TEST_DATA / "expected-advisories.json"
    result = [adv.to_advisory_data().to_dict() for adv in AdvisoryV2.objects.all()]
    util_tests.check_results_against_json(result, expected_file)


@pytest.mark.parametrize(
    "published_date, advisory_id, expected_url",
    [
        (
            "2022-05-17T05:10:31Z",
            "GHSA-2655-q453-22f9",
            "https://raw.githubusercontent.com/github/advisory-database/refs/heads/main/advisories/github-reviewed/2022/05/GHSA-2655-q453-22f9/GHSA-2655-q453-22f9.json",
        ),
        (
            "2017-10-24T18:33:37Z",
            "GHSA-4936-rj25-6wm6",
            "https://raw.githubusercontent.com/github/advisory-database/refs/heads/main/advisories/github-reviewed/2017/10/GHSA-4936-rj25-6wm6/GHSA-4936-rj25-6wm6.json",
        ),
    ],
)
def test_build_github_repo_advisory_url(published_date, advisory_id, expected_url):
    assert build_github_repo_advisory_url(published_date, advisory_id, logger=print) == expected_url
