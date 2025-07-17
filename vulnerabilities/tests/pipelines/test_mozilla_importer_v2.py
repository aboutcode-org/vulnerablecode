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
from textwrap import dedent

from vulnerabilities.pipelines.v2_importers.mozilla_importer import extract_description_from_html
from vulnerabilities.pipelines.v2_importers.mozilla_importer import get_severity_from_impact
from vulnerabilities.pipelines.v2_importers.mozilla_importer import mfsa_id_from_filename
from vulnerabilities.pipelines.v2_importers.mozilla_importer import parse_affected_packages
from vulnerabilities.pipelines.v2_importers.mozilla_importer import parse_md_advisory
from vulnerabilities.pipelines.v2_importers.mozilla_importer import parse_yml_advisory


def test_mfsa_id_from_filename():
    assert mfsa_id_from_filename("mfsa2022-01.md") == "mfsa2022-01"
    assert mfsa_id_from_filename("mfsa2022-099.yml") == "mfsa2022-099"
    assert mfsa_id_from_filename("notmfsa.txt") is None


def test_get_severity_from_impact():
    assert get_severity_from_impact("Critical").value == "critical"
    assert get_severity_from_impact("Moderate").value == "medium"
    assert get_severity_from_impact("Low").value == "low"
    assert get_severity_from_impact("Random Text").value == "none"
    assert get_severity_from_impact(None).value == "none"


def test_extract_description_from_html():
    md_text = dedent(
        """
        ### Description

        This vulnerability affects Firefox.

        It could allow attackers to execute arbitrary code.

        ### Impact

        Critical
    """
    )
    expected = (
        "This vulnerability affects Firefox.\nIt could allow attackers to execute arbitrary code."
    )
    assert extract_description_from_html(md_text) == expected


def test_parse_affected_packages_valid():
    packages = ["firefox 89.0", "thunderbird 78.10"]
    result = list(parse_affected_packages(packages))
    assert len(result) == 2
    assert result[0].package.name == "firefox"
    assert str(result[0].fixed_version) == "89.0.0"


def test_parse_affected_packages_invalid():
    packages = ["firefox 89.0.0.1", "invalidpackage"]
    result = list(parse_affected_packages(packages))
    assert len(result) == 0  # invalid SemVer or malformed


def test_parse_yml_advisory(tmp_path: Path):
    advisory = {
        "announced": "2022-01-01",
        "description": "<p>This is a test</p>",
        "impact": "High",
        "fixed_in": ["firefox 89.0"],
        "advisories": {
            "CVE-2022-1234": {"description": "<p>Memory safety issue</p>", "impact": "Critical"}
        },
    }
    file = tmp_path / "mfsa2022-01.yml"
    file.write_text(json.dumps(advisory))

    results = list(
        parse_yml_advisory("mfsa2022-01", file.open(), advisory_url="https://example.com")
    )
    assert len(results) == 1 or len(results) == 2
    assert all(isinstance(r.summary, str) for r in results)
