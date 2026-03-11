import json
from io import BytesIO
from unittest.mock import patch
from zipfile import ZipFile

import pytest

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines.v2_importers.pysec_importer import (
    PyPIImporterPipeline,  # Path to the PyPI Importer
)


@pytest.fixture
def mock_zip_data():
    # Create mock zip data for testing
    zip_buffer = BytesIO()
    with ZipFile(zip_buffer, mode="w") as zip_file:
        # Create a sample advisory file inside the zip
        advisory_data = {
            "advisory_id": "PYSEC-1234",
            "summary": "Sample PyPI advisory",
            "references": [{"url": "https://pypi.org/advisory/PYSEC-1234"}],
            "package": {"name": "example-package"},
            "affected_versions": ">=1.0.0,<=2.0.0",
        }
        # Save the sample advisory as a JSON file
        with zip_file.open("PYSEC-1234.json", "w") as f:
            f.write(json.dumps(advisory_data).encode("utf-8"))
    zip_buffer.seek(0)
    return zip_buffer


@pytest.fixture
def mock_requests_get():
    with patch("requests.get") as mock:
        yield mock


def test_fetch_zip(mock_requests_get, mock_zip_data):
    # Mock the `requests.get` to return the mock zip data
    mock_requests_get.return_value.content = mock_zip_data.read()

    pipeline = PyPIImporterPipeline()

    # Call the `fetch_zip` method
    pipeline.fetch_zip()

    # Reset the position of mock_zip_data to 0 before comparing
    mock_zip_data.seek(0)

    # Verify that the zip file content is correctly assigned
    assert pipeline.advisory_zip == mock_zip_data.read()


def test_advisories_count(mock_requests_get, mock_zip_data):
    # Mock the `requests.get` to return the mock zip data
    mock_requests_get.return_value.content = mock_zip_data.read()

    pipeline = PyPIImporterPipeline()

    # Fetch the zip data
    pipeline.fetch_zip()

    # Test advisories count
    count = pipeline.advisories_count()

    # Verify that it correctly counts the number of advisory files starting with 'PYSEC-'
    assert count == 1


def test_collect_advisories(mock_requests_get, mock_zip_data):
    # Mock the `requests.get` to return the mock zip data
    mock_requests_get.return_value.content = mock_zip_data.read()

    pipeline = PyPIImporterPipeline()

    # Fetch the zip data
    pipeline.fetch_zip()

    # Mock the `parse_advisory_data_v2` function to return a dummy AdvisoryData
    with patch(
        "vulnerabilities.pipelines.v2_importers.pysec_importer.parse_advisory_data_v3"
    ) as mock_parse:
        mock_parse.return_value = AdvisoryDataV2(
            advisory_id="PYSEC-1234",
            summary="Sample PyPI advisory",
            references=[{"url": "https://pypi.org/advisory/PYSEC-1234"}],
            affected_packages=[],
            weaknesses=[],
            url="https://pypi.org/advisory/PYSEC-1234",
        )

        # Call the `collect_advisories` method
        advisories = list(pipeline.collect_advisories())

        # Ensure we have 1 advisory
        assert len(advisories) == 1

        # Verify advisory data
        advisory = advisories[0]
        assert advisory.advisory_id == "PYSEC-1234"
        assert advisory.summary == "Sample PyPI advisory"
        assert advisory.url == "https://pypi.org/advisory/PYSEC-1234"


def test_collect_advisories_invalid_file(mock_requests_get, mock_zip_data):
    # Create a mock zip with an invalid file name
    zip_buffer = BytesIO()
    with ZipFile(zip_buffer, mode="w") as zip_file:
        zip_file.writestr("INVALID_FILE.txt", "Invalid content")

    zip_buffer.seek(0)
    mock_requests_get.return_value.content = zip_buffer.read()

    pipeline = PyPIImporterPipeline()

    # Fetch the zip data
    pipeline.fetch_zip()

    # Mock the `parse_advisory_data_v2` function
    with patch(
        "vulnerabilities.pipelines.v2_importers.pysec_importer.parse_advisory_data_v3"
    ) as mock_parse:
        mock_parse.return_value = AdvisoryDataV2(
            advisory_id="PYSEC-1234",
            summary="Sample PyPI advisory",
            references=[{"url": "https://pypi.org/advisory/PYSEC-1234"}],
            affected_packages=[],
            weaknesses=[],
            url="https://pypi.org/advisory/PYSEC-1234",
        )

        # Call the `collect_advisories` method and check the logging for invalid file
        with patch(
            "vulnerabilities.pipelines.VulnerableCodeBaseImporterPipelineV2.log"
        ) as mock_log:
            advisories = list(pipeline.collect_advisories())

            # Ensure no advisories were yielded due to the invalid file
            assert len(advisories) == 0
