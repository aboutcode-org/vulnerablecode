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
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines.v2_importers.postgresql_importer import PostgreSQLImporterPipeline

HTML_PAGE_WITH_LINKS = """
<html>
  <body>
    <h3>Security Advisory</h3>
    <p><a href="/support/security/advisory1.html">Advisory 1</a></p>
    <h3>Another Advisory</h3>
    <p><a href="/support/security/advisory2.html">Advisory 2</a></p>
  </body>
</html>
"""

HTML_ADVISORY = """
<html>
  <body>
    <table>
      <tbody>
        <tr>
          <td>
          <span class="nobr"><a href="/support/security/CVE-2022-1234/">CVE-2022-1234</a></span><br>
          <a href="/about/news/postgresql-175-169-1513-1418-and-1321-released-3072/">Announcement</a><br>
        </td>
          <td>10.0, 10.1</td>
          <td>10.2</td>
          <td><a href="/vector?vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">9.8</a></td>
          <td>Description of the issue</td>
        </tr>
      </tbody>
    </table>
  </body>
</html>
"""


@pytest.fixture
def importer():
    return PostgreSQLImporterPipeline()


@patch("vulnerabilities.pipelines.v2_importers.postgresql_importer.requests.get")
def test_collect_links(mock_get, importer):
    mock_get.return_value.content = HTML_PAGE_WITH_LINKS.encode("utf-8")

    importer.collect_links()

    assert len(importer.links) == 3  # base + 2 new
    assert any("advisory1.html" in link for link in importer.links)
    assert any("advisory2.html" in link for link in importer.links)


@patch("vulnerabilities.pipelines.v2_importers.postgresql_importer.requests.get")
def test_advisories_count(mock_get, importer):
    mock_get.return_value.content = HTML_PAGE_WITH_LINKS.encode("utf-8")

    count = importer.advisories_count()
    assert count >= 3


@patch("vulnerabilities.pipelines.v2_importers.postgresql_importer.requests.get")
def test_collect_advisories(mock_get, importer):
    importer.links = {
        "https://www.postgresql.org/support/security/advisory1.html",
        "https://www.postgresql.org/support/security/advisory2.html",
    }

    mock_get.return_value.content = HTML_ADVISORY.encode("utf-8")

    advisories = list(importer.collect_advisories())

    assert len(advisories) == 2
    advisory = advisories[0]
    assert isinstance(advisory, AdvisoryData)
    assert advisory.advisory_id == "CVE-2022-1234"
    assert "Description of the issue" in advisory.summary
    assert len(advisory.references_v2) > 0
    assert advisory.affected_packages[0].package.name == "postgresql"
    assert str(advisory.affected_packages[0].fixed_version) == "10.2"
    assert advisory.affected_packages[0].affected_version_range.contains(SemverVersion("10.0.0"))
    assert advisory.affected_packages[0].affected_version_range.contains(SemverVersion("10.1.0"))


@patch("vulnerabilities.pipelines.v2_importers.postgresql_importer.requests.get")
def test_collect_advisories_with_no_fixed_version(mock_get, importer):
    no_fix_html = """
    <html>
      <body>
        <table>
          <tbody>
            <tr>
              <td>
                <span class="nobr"><a href="/support/security/CVE-2023-5678/">CVE-2023-5678</a></span><br>
                <a href="/about/news/postgresql-175-169-1513-1418-and-1321-released-3072/">Announcement</a><br>
             </td>
              <td>9.5, 9.6</td>
              <td></td>
              <td></td>
              <td>Unpatched issue</td>
            </tr>
          </tbody>
        </table>
      </body>
    </html>
    """

    def side_effect(url, *args, **kwargs):
        if "advisory" not in url:
            return MagicMock(content=HTML_PAGE_WITH_LINKS.encode("utf-8"))
        return MagicMock(content=no_fix_html.encode("utf-8"))

    mock_get.side_effect = side_effect

    advisories = list(importer.collect_advisories())

    assert len(advisories) == 2
    advisory = advisories[0]
    assert advisory.advisory_id == "CVE-2023-5678"
    assert advisory.affected_packages[0].fixed_version is None
    assert advisory.affected_packages[0].affected_version_range.contains(SemverVersion("9.5"))


@patch("vulnerabilities.pipelines.v2_importers.postgresql_importer.requests.get")
def test_cvss_parsing(mock_get, importer):
    mock_get.side_effect = lambda url, *args, **kwargs: MagicMock(
        content=HTML_ADVISORY.encode("utf-8")
    )

    importer.links = {"https://www.postgresql.org/support/security/advisory1.html"}

    advisories = list(importer.collect_advisories())

    assert len(advisories) == 1
    reference = advisories[0].references_v2[0]

    severity = advisories[0].severities[0]
    assert severity.system.identifier == "cvssv3"
    assert severity.value == "9.8"
    assert "AV:N/AC:L/PR:N/UI:N" in severity.scoring_elements
