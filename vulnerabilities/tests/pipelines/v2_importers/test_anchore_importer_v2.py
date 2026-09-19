#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.

import json
import logging
import pytest

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines.v2_importers.anchore_importer import AnchoreImporterPipeline
from vulnerabilities.pipelines.v2_importers.anchore_importer import parse_anchore_advisory


class DummyVCSResponse:
    ''' A dummy class to simulate the response from fetch_via_vcs for testing purposes.
    '''
    def __init__(self, dest_dir):
        self.dest_dir = str(dest_dir)

@pytest.fixture
def pipeline():
    return AnchoreImporterPipeline() # the actual pipeline instance used in tests


def test_parse_anchore_advisory_maps_basic_fields(tmp_path):
    ''' 
    Parse an Anchore advisory, the basic information gets put into the right places
    '''
    file_path = tmp_path / "data" / "nested" / "CVE-2024-0001.json"
    file_path.parent.mkdir(parents=True)

    # fake raw data 
    raw_data = {
        "description": "A sample advisory",
        "_annotation": {
            "description": "Ignored annotation description",
            "references": ["https://example.com/annotation"],
        },
        "cve": {
            "references": {
                "reference_data": [{"url": "https://example.com/cve-reference"}],
            }
        },
    }

    advisory = parse_anchore_advisory(
        raw_data=raw_data,
        file_path=file_path,
        base_path=tmp_path,
        logger=logging.getLogger(__name__),
    )

    assert isinstance(advisory, AdvisoryDataV2)
    assert advisory.advisory_id == "anchore/CVE-2024-0001"
    assert advisory.aliases == ["CVE-2024-0001"]
    assert advisory.summary == "A sample advisory"
    assert [ref.url for ref in advisory.references] == [
        "https://example.com/annotation",
        "https://example.com/cve-reference",
    ]
    assert advisory.url == (
        "https://github.com/anchore/nvd-data-overrides/blob/main/data/nested/CVE-2024-0001.json"
    )


def test_collect_advisories_yields_advisories_from_data_directory(tmp_path, pipeline):
    '''
    Test if it extracts advisories from the data directory 
    - Find the data directory
    - Find the JSON files
    - Open the files
    - Read the JSON.
    - Parse the data
    - Create AdvisoryDataV2 objects
    - Return those advisories
    '''
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True)

    first = data_dir / "CVE-2024-0001.json"
    first.write_text(
        json.dumps(
            {
                "description": "First advisory",
                "_annotation": {"references": ["https://example.com/one"]},
                "cve": {"references": {"reference_data": [{"url": "https://example.com/one-bis"}]}}
            }
        )
    )

    second = data_dir / "CVE-2024-0002.json"
    second.write_text(
        json.dumps(
            {
                "description": "Second advisory",
                "_annotation": {"references": ["https://example.com/two"]},
                "cve": {"references": {"reference_data": []}},
            }
        )
    )

    pipeline.vcs_response = DummyVCSResponse(tmp_path)

    advisories = list(pipeline.collect_advisories())
    advisory_ids = sorted(advisory.advisory_id for advisory in advisories)

    assert advisory_ids == ["anchore/CVE-2024-0001", "anchore/CVE-2024-0002"]
    assert advisories[0].summary == "First advisory"
    assert advisories[1].summary == "Second advisory"


def test_collect_advisories_returns_no_results_for_empty_data_directory(tmp_path, pipeline):
    '''
    Test that if the data directory is empty, no advisories are returned.
    '''
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True)
    pipeline.vcs_response = DummyVCSResponse(tmp_path)

    assert list(pipeline.collect_advisories()) == []


def test_collect_advisories_handles_malformed_json(tmp_path, pipeline):
    '''
    Test a broken JSON file in the data directory, it should log a warning and continue.
    '''
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True)
    (data_dir / "CVE-2024-0003.json").write_text("{not valid json")

    pipeline.vcs_response = DummyVCSResponse(tmp_path)
    messages = []
    pipeline.log = lambda message, level=logging.INFO: messages.append((message, level))

    assert list(pipeline.collect_advisories()) == []
    assert any("Failed to process advisory" in message for message, _ in messages)

