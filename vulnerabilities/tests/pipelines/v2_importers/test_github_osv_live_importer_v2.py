import json
from unittest import mock

from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines.v2_importers.github_osv_live_importer import (
    GithubOSVLiveImporterPipeline,
)

SAMPLE_OSV = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "summary": "Sample summary",
    "details": "Sample details",
    "aliases": ["CVE-2021-99999"],
    "affected": [
        {
            "package": {"name": "sample", "ecosystem": "PyPI"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}]}
            ],
            "versions": ["1.0.0", "1.1.0"],
        }
    ],
    "database_specific": {"cwe_ids": ["CWE-79"]},
}


@mock.patch(
    "vulnerabilities.pipelines.v2_importers.github_osv_live_importer.fetch_github_osv_advisories_for_purl"
)
def test_github_osv_live_importer_found_with_version(mock_fetch):
    mock_fetch.return_value = [json.loads(json.dumps(SAMPLE_OSV))]
    purl = PackageURL(type="pypi", name="sample", version="1.1.0")
    pipeline = GithubOSVLiveImporterPipeline(purl=purl)
    pipeline.get_purl_inputs()
    pipeline.advisories_count()
    advisories = list(pipeline.collect_advisories())
    assert len(advisories) == 1
    adv = advisories[0]
    assert isinstance(adv, AdvisoryData)
    assert adv.advisory_id == "GHSA-xxxx-yyyy-zzzz"
    assert "CVE-2021-99999" in adv.aliases
    assert adv.summary.startswith("Sample")
    assert adv.affected_packages
    assert adv.affected_packages[0].package.type == "pypi"


@mock.patch(
    "vulnerabilities.pipelines.v2_importers.github_osv_live_importer.fetch_github_osv_advisories_for_purl"
)
def test_github_osv_live_importer_none_found_with_version(mock_fetch):
    mock_fetch.return_value = [json.loads(json.dumps(SAMPLE_OSV))]
    purl = PackageURL(type="pypi", name="sample", version="1.2.0")
    pipeline = GithubOSVLiveImporterPipeline(purl=purl)
    pipeline.get_purl_inputs()
    pipeline.advisories_count()
    advisories = list(pipeline.collect_advisories())
    assert advisories == []
