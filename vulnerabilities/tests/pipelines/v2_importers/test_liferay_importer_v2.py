#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines.v2_importers.liferay_importer import LiferayImporterPipeline
from vulnerabilities.pipelines.v2_importers.liferay_importer import build_affected_packages
from vulnerabilities.pipelines.v2_importers.liferay_importer import extract_cve_id
from vulnerabilities.pipelines.v2_importers.liferay_importer import extract_version_numbers
from vulnerabilities.pipelines.v2_importers.liferay_importer import parse_advisory_page
from vulnerabilities.pipelines.v2_importers.liferay_importer import parse_date
from vulnerabilities.pipelines.v2_importers.liferay_importer import parse_feed_entries
from vulnerabilities.pipelines.v2_importers.liferay_importer import parse_severity

SAMPLE_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Liferay Security Advisories</title>
  <entry>
    <title>CVE-2024-26268 User enumeration via timing analysis</title>
    <link rel="alternate" href="https://liferay.dev/portal/security/known-vulnerabilities/-/asset_publisher/jekt/content/cve-2024-26268"/>
    <published>2024-02-20T13:10:00Z</published>
  </entry>
  <entry>
    <title>CVE-2023-42626 Some other vulnerability</title>
    <link rel="alternate" href="https://liferay.dev/portal/security/known-vulnerabilities/-/asset_publisher/jekt/content/cve-2023-42626"/>
    <published>2023-11-01T10:00:00Z</published>
  </entry>
</feed>"""

SAMPLE_ADVISORY_HTML = """<html><body>
<h3>Description</h3>
<p>User enumeration vulnerability in Liferay Portal and Liferay DXP allows remote
attackers to determine if an account exist in the application by comparing the
request's response time.</p>
<h3>Severity</h3>
<p>5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)</p>
<h3>Affected Version(s)</h3>
<ul>
  <li>Liferay Portal 7.4.0 through 7.4.3.26</li>
  <li>Liferay Portal 7.3.0 through 7.3.7</li>
  <li>Liferay DXP 7.4 before update 27</li>
  <li>Liferay DXP 7.3 before update 8</li>
</ul>
<h3>Fixed Version(s)</h3>
<ul>
  <li>Liferay Portal 7.4.3.27</li>
  <li>Liferay DXP 7.4 update 27</li>
</ul>
<h3>Acknowledgments</h3>
<p>This issue was reported by Barnabas Horvath (T4r0)</p>
</body></html>"""


def test_extract_cve_id():
    assert extract_cve_id("CVE-2024-26268 User enumeration vulnerability") == "CVE-2024-26268"
    assert extract_cve_id("No CVE here") == ""
    assert extract_cve_id("CVE-2023-42626 title") == "CVE-2023-42626"


def test_parse_feed_entries():
    entries = parse_feed_entries(SAMPLE_FEED)
    assert len(entries) == 2
    cve_ids = [e[0] for e in entries]
    assert "CVE-2024-26268" in cve_ids
    assert "CVE-2023-42626" in cve_ids
    assert "liferay.dev" in entries[0][1]


def test_parse_severity_with_vector():
    sev = parse_severity("5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)")
    assert sev is not None
    assert sev.value == "5.3"
    assert sev.scoring_elements == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    assert sev.system.identifier == "cvssv3.1"


def test_parse_severity_score_only():
    sev = parse_severity("7.5")
    assert sev is not None
    assert sev.value == "7.5"
    assert sev.scoring_elements == ""


def test_parse_severity_empty():
    assert parse_severity("") is None
    assert parse_severity(None) is None


def test_parse_date_utc():
    dt = parse_date("2024-02-20T13:10:00Z")
    assert dt is not None
    assert dt.year == 2024
    assert dt.month == 2
    assert dt.day == 20
    assert dt.tzinfo is not None


def test_parse_date_empty():
    assert parse_date("") is None
    assert parse_date(None) is None


def test_extract_version_numbers():
    assert extract_version_numbers(["Liferay Portal 7.4.3.27"]) == ["7.4.3.27"]
    assert extract_version_numbers(["Liferay Portal 7.4.0 through 7.4.3.26"]) == ["7.4.0", "7.4.3.26"]
    assert extract_version_numbers(["Liferay DXP 7.4 update 27"]) == ["7.4"]
    assert extract_version_numbers([]) == []


def test_build_affected_packages_portal_and_dxp():
    affected = [
        "Liferay Portal 7.4.0 through 7.4.3.26",
        "Liferay DXP 7.4 before update 27",
    ]
    fixed = [
        "Liferay Portal 7.4.3.27",
        "Liferay DXP 7.4 update 27",
    ]
    packages = build_affected_packages(affected, fixed)
    assert len(packages) == 2
    names = {p.package.name for p in packages}
    assert "liferay-portal" in names
    assert "liferay-dxp" in names


def test_build_affected_packages_portal_only():
    packages = build_affected_packages(
        ["Liferay Portal 7.4.0 through 7.4.3.26"],
        ["Liferay Portal 7.4.3.27"],
    )
    assert len(packages) == 1
    assert packages[0].package.name == "liferay-portal"


def test_build_affected_packages_empty():
    packages = build_affected_packages([], [])
    assert packages == []


def test_parse_advisory_page():
    advisory_url = "https://liferay.dev/portal/security/known-vulnerabilities/-/asset_publisher/jekt/content/cve-2024-26268"
    advisory = parse_advisory_page(
        "CVE-2024-26268",
        advisory_url,
        "2024-02-20T13:10:00Z",
        SAMPLE_ADVISORY_HTML,
    )
    assert isinstance(advisory, AdvisoryDataV2)
    assert advisory.advisory_id == "CVE-2024-26268"
    assert "enumeration" in advisory.summary
    assert len(advisory.severities) == 1
    assert advisory.severities[0].value == "5.3"
    assert advisory.severities[0].scoring_elements == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    assert len(advisory.affected_packages) == 2
    assert advisory.date_published is not None
    assert advisory.url == advisory_url


@patch("vulnerabilities.pipelines.v2_importers.liferay_importer.requests.get")
def test_collect_advisories(mock_get):
    feed_response = MagicMock()
    feed_response.text = SAMPLE_FEED
    feed_response.raise_for_status = MagicMock()

    advisory_response = MagicMock()
    advisory_response.text = SAMPLE_ADVISORY_HTML
    advisory_response.raise_for_status = MagicMock()

    mock_get.side_effect = [feed_response, advisory_response, advisory_response]

    pipeline = LiferayImporterPipeline()
    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 2
    assert all(isinstance(a, AdvisoryDataV2) for a in advisories)
    cve_ids = {a.advisory_id for a in advisories}
    assert "CVE-2024-26268" in cve_ids
