#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from pathlib import Path
from unittest.mock import MagicMock
from unittest.mock import patch

from vulnerabilities.pipelines.v2_importers.anchore_importer import AnchoreImporterPipeline
from vulnerabilities.pipelines.v2_importers.anchore_importer import extract_cpes
from vulnerabilities.tests.util_tests import VULNERABLECODE_REGEN_TEST_FIXTURES as REGEN

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "anchore"


def test_extract_cpes_single_node():
    configurations = [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "criteria": "cpe:2.3:a:nvidia:cuda_toolkit:*:*:*:*:*:*:*:*",
                            "vulnerable": True,
                        }
                    ],
                    "negate": False,
                    "operator": "OR",
                }
            ]
        }
    ]
    result = extract_cpes(configurations)
    assert result == ["cpe:2.3:a:nvidia:cuda_toolkit:*:*:*:*:*:*:*:*"]


def test_extract_cpes_multiple_nodes():
    configurations = [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "criteria": "cpe:2.3:a:nvidia:chatrtx:*:*:*:*:*:*:*:*",
                            "vulnerable": True,
                        }
                    ],
                    "operator": "OR",
                },
                {
                    "cpeMatch": [
                        {
                            "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
                            "vulnerable": False,
                        }
                    ],
                    "operator": "OR",
                },
            ],
            "operator": "AND",
        }
    ]
    result = extract_cpes(configurations)
    assert result == [
        "cpe:2.3:a:nvidia:chatrtx:*:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*",
    ]


def test_extract_cpes_empty():
    assert extract_cpes([]) == []
    assert extract_cpes([{"nodes": []}]) == []


def test_extract_cpes_no_duplicates():
    configurations = [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                            "vulnerable": True,
                        },
                        {
                            "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
                            "vulnerable": True,
                        },
                    ],
                    "operator": "OR",
                }
            ]
        }
    ]
    result = extract_cpes(configurations)
    assert result == ["cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"]


def test_parse_advisory_software_cve():
    pipeline = AnchoreImporterPipeline()
    file = TEST_DATA / "CVE-2024-0072.json"
    advisory = pipeline.parse_advisory(file)

    assert advisory is not None
    assert advisory.advisory_id == "CVE-2024-0072"
    assert "NVIDIA CUDA toolkit" in advisory.summary
    assert advisory.weaknesses == []
    assert advisory.aliases == []

    ref_ids = [ref.reference_id for ref in advisory.references]
    assert "cpe:2.3:a:nvidia:cuda_toolkit:*:*:*:*:*:*:*:*" in ref_ids
    assert "CVE-2024-0072" in ref_ids

    ref_urls = [ref.url for ref in advisory.references]
    assert "https://nvidia.custhelp.com/app/answers/detail/a_id/5517" in ref_urls

    assert advisory.date_published is not None
    assert advisory.url == (
        "https://github.com/anchore/nvd-data-overrides/blob/main/" "data/anchore/CVE-2024-0072.json"
    )


def test_parse_advisory_with_multiple_nodes():
    pipeline = AnchoreImporterPipeline()
    file = TEST_DATA / "CVE-2024-0082.json"
    advisory = pipeline.parse_advisory(file)

    assert advisory is not None
    assert advisory.advisory_id == "CVE-2024-0082"

    ref_ids = [ref.reference_id for ref in advisory.references]
    assert "cpe:2.3:a:nvidia:chatrtx:*:*:*:*:*:*:*:*" in ref_ids
    assert "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*" in ref_ids


def test_parse_advisory_skips_hardware_only():
    pipeline = AnchoreImporterPipeline()
    file = TEST_DATA / "CVE-2024-9999-hw.json"
    advisory = pipeline.parse_advisory(file)

    assert advisory is None


def test_parse_advisory_with_expected_output(regen=REGEN):
    expected_file = TEST_DATA / "anchore-expected.json"
    pipeline = AnchoreImporterPipeline()

    results = []
    for test_file in sorted(TEST_DATA.glob("CVE-2024-00*.json")):
        advisory = pipeline.parse_advisory(test_file)
        if advisory:
            results.append(advisory.to_dict())

    if regen:
        with open(expected_file, "w") as f:
            json.dump(results, f, indent=2)
        expected = results
    else:
        with open(expected_file) as f:
            expected = json.load(f)

    assert results == expected


def test_clone():
    with patch(
        "vulnerabilities.pipelines.v2_importers.anchore_importer.fetch_via_vcs"
    ) as mock_fetch:
        mock_response = MagicMock()
        mock_response.dest_dir = "/mock/repo"
        mock_fetch.return_value = mock_response

        pipeline = AnchoreImporterPipeline()
        pipeline.clone()

        mock_fetch.assert_called_once_with(pipeline.repo_url)
        assert pipeline.data_path == Path("/mock/repo/data")


def test_advisories_count(tmp_path):
    data_dir = tmp_path / "data" / "2024"
    data_dir.mkdir(parents=True)

    (data_dir / "CVE-2024-0001.json").write_text("{}")
    (data_dir / "CVE-2024-0002.json").write_text("{}")
    (data_dir / "not-a-cve.json").write_text("{}")

    pipeline = AnchoreImporterPipeline()
    pipeline.data_path = tmp_path / "data"

    assert pipeline.advisories_count() == 2


def test_clean_downloads():
    mock_response = MagicMock()
    pipeline = AnchoreImporterPipeline()
    pipeline.vcs_response = mock_response

    pipeline.clean_downloads()

    mock_response.delete.assert_called_once()


def test_on_failure():
    pipeline = AnchoreImporterPipeline()
    pipeline.vcs_response = MagicMock()

    with patch.object(pipeline, "clean_downloads") as mock_clean:
        pipeline.on_failure()
        mock_clean.assert_called_once()
