import json
from io import BytesIO
from unittest.mock import patch
from zipfile import ZipFile

import pytest
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData


@pytest.fixture
def mock_zip_data():
    # Create a zip with two advisories for the same package with different versions
    zip_buffer = BytesIO()
    with ZipFile(zip_buffer, mode="w") as zip_file:
        advisory1 = {
            "advisory_id": "PYSEC-1001",
            "summary": "Vuln in foo",
            "affected": [
                {
                    "package": {"name": "foo", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}],
                        }
                    ],
                }
            ],
        }
        advisory2 = {
            "advisory_id": "PYSEC-1002",
            "summary": "Vuln in foo, later version",
            "affected": [
                {
                    "package": {"name": "foo", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "2.5.0"}, {"fixed": "3.0.0"}],
                        }
                    ],
                }
            ],
        }
        advisory3 = {
            "advisory_id": "PYSEC-2000",
            "summary": "Vuln in bar",
            "affected": [
                {
                    "package": {"name": "bar", "ecosystem": "PyPI"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0.1.0"}, {"fixed": "0.2.0"}],
                        }
                    ],
                }
            ],
        }
        zip_file.writestr("PYSEC-1001.json", json.dumps(advisory1))
        zip_file.writestr("PYSEC-1002.json", json.dumps(advisory2))
        zip_file.writestr("PYSEC-2000.json", json.dumps(advisory3))
    zip_buffer.seek(0)
    return zip_buffer


def test_package_with_version_affected(mock_zip_data):
    from vulnerabilities.pipelines.v2_importers.pysec_live_importer import PySecLiveImporterPipeline

    purl = PackageURL(type="pypi", name="foo", version="1.5.0")

    with patch("requests.get") as mock_get:
        mock_get.return_value.content = mock_zip_data.read()

        with patch("vulnerabilities.importers.osv.parse_advisory_data_v2") as mock_parse:

            def parse_side_effect(raw_data, supported_ecosystems, advisory_url, advisory_text):
                return AdvisoryData(
                    advisory_id=raw_data["advisory_id"],
                    summary=raw_data["summary"],
                    references_v2=[{"url": advisory_url}],
                    affected_packages=[],
                    weaknesses=[],
                    url=advisory_url,
                )

            mock_parse.side_effect = parse_side_effect

            pipeline = PySecLiveImporterPipeline(purl=purl)
            pipeline.get_purl_inputs()
            pipeline.fetch_zip()
            advisories = list(pipeline.collect_advisories())

            # Only PYSEC-1001 should match
            assert len(advisories) == 1
            assert advisories[0].advisory_id == "PYSEC-1001"


def test_package_with_version_not_affected(mock_zip_data):
    from vulnerabilities.pipelines.v2_importers.pysec_live_importer import PySecLiveImporterPipeline

    purl = PackageURL(type="pypi", name="foo", version="2.2.0")

    with patch("requests.get") as mock_get:
        mock_get.return_value.content = mock_zip_data.read()

        with patch("vulnerabilities.importers.osv.parse_advisory_data_v2") as mock_parse:
            mock_parse.return_value = AdvisoryData(
                advisory_id="PYSEC-1002",
                summary="Vuln in foo, later version",
                references_v2=[{"url": "dummy"}],
                affected_packages=[],
                weaknesses=[],
                url="dummy",
            )

            pipeline = PySecLiveImporterPipeline(purl=purl)
            pipeline.get_purl_inputs()
            pipeline.fetch_zip()
            advisories = list(pipeline.collect_advisories())

            # No advisories should match
            assert len(advisories) == 0


def test_nonexistent_package(mock_zip_data):
    from vulnerabilities.pipelines.v2_importers.pysec_live_importer import PySecLiveImporterPipeline

    purl = PackageURL(type="pypi", name="baz", version="1.0.0")

    with patch("requests.get") as mock_get:
        mock_get.return_value.content = mock_zip_data.read()

        pipeline = PySecLiveImporterPipeline(purl=purl)
        pipeline.get_purl_inputs()
        pipeline.fetch_zip()
        advisories = list(pipeline.collect_advisories())

        assert len(advisories) == 0
