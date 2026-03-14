#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime
from datetime import timezone
from unittest.mock import MagicMock
from unittest.mock import patch
from xml.etree import ElementTree

import pytest
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines.v2_importers.apache_log4j_importer import (
    ApacheLog4jImporterPipeline,
)
from vulnerabilities.pipelines.v2_importers.apache_log4j_importer import CDX_NS
from vulnerabilities.pipelines.v2_importers.apache_log4j_importer import parse_advisory
from vulnerabilities.pipelines.v2_importers.apache_log4j_importer import parse_affected_packages
from vulnerabilities.pipelines.v2_importers.apache_log4j_importer import parse_date
from vulnerabilities.pipelines.v2_importers.apache_log4j_importer import parse_references
from vulnerabilities.pipelines.v2_importers.apache_log4j_importer import parse_severities
from vulnerabilities.pipelines.v2_importers.apache_log4j_importer import parse_weaknesses

# Minimal VDR XML document with two vulnerabilities for use in mock tests.
SAMPLE_VDR_XML = """<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
  <vulnerabilities>
    <vulnerability>
      <id>CVE-2021-44228</id>
      <source>
        <name>NVD</name>
        <url>https://nvd.nist.gov/vuln/detail/CVE-2021-44228</url>
      </source>
      <ratings>
        <rating>
          <source><name>NVD</name></source>
          <score>10.0</score>
          <severity>critical</severity>
          <method>CVSSv3</method>
          <vector>AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</vector>
        </rating>
      </ratings>
      <cwes>
        <cwe>20</cwe>
        <cwe>400</cwe>
        <cwe>502</cwe>
        <cwe>917</cwe>
      </cwes>
      <description>JNDI lookup exploitation in Log4j.</description>
      <published>2021-12-10T00:00:00Z</published>
      <affects>
        <target>
          <ref>pkg:maven/org.apache.logging.log4j/log4j-core?type=jar</ref>
          <versions>
            <version>
              <range>vers:maven/&gt;=2.0-beta9|&lt;2.15.0</range>
            </version>
          </versions>
        </target>
      </affects>
    </vulnerability>
    <vulnerability>
      <id>CVE-2025-68161</id>
      <source>
        <name>NVD</name>
        <url>https://nvd.nist.gov/vuln/detail/CVE-2025-68161</url>
      </source>
      <ratings>
        <rating>
          <score>6.3</score>
          <severity>medium</severity>
          <method>CVSSv4</method>
          <vector>AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:L/SA:N</vector>
        </rating>
      </ratings>
      <cwes>
        <cwe>297</cwe>
      </cwes>
      <description>TLS hostname verification missing in Socket Appender.</description>
      <published>2025-12-18T16:09:38Z</published>
      <affects>
        <target>
          <ref>pkg:maven/org.apache.logging.log4j/log4j-core?type=jar</ref>
          <versions>
            <version>
              <range>vers:maven/&gt;=2.0-beta9|&lt;2.25.3</range>
            </version>
          </versions>
        </target>
      </affects>
    </vulnerability>
  </vulnerabilities>
</bom>
"""


def make_vuln_el(xml_fragment):
    """Wrap an inner XML snippet in a bom root and return the <vulnerability> element."""
    wrapped = f'<bom xmlns="{CDX_NS}">{xml_fragment}</bom>'
    root = ElementTree.fromstring(wrapped)
    return root.find(f"{{{CDX_NS}}}vulnerability")


# --- parse_date ---


def test_parse_date_valid_utc():
    result = parse_date("2021-12-10T00:00:00Z")
    assert result == datetime(2021, 12, 10, 0, 0, tzinfo=timezone.utc)


def test_parse_date_empty():
    assert parse_date("") is None


def test_parse_date_invalid():
    assert parse_date("not-a-date") is None


# --- parse_weaknesses ---


def test_parse_weaknesses_multiple():
    vuln_el = make_vuln_el(
        "<vulnerability><cwes><cwe>20</cwe><cwe>502</cwe></cwes></vulnerability>"
    )
    assert parse_weaknesses(vuln_el) == [20, 502]


def test_parse_weaknesses_none():
    vuln_el = make_vuln_el("<vulnerability></vulnerability>")
    assert parse_weaknesses(vuln_el) == []


def test_parse_weaknesses_ignores_non_numeric():
    vuln_el = make_vuln_el("<vulnerability><cwes><cwe>abc</cwe><cwe>79</cwe></cwes></vulnerability>")
    assert parse_weaknesses(vuln_el) == [79]


# --- parse_severities ---


def test_parse_severities_cvssv3():
    vuln_el = make_vuln_el(
        """<vulnerability>
          <ratings>
            <rating>
              <score>10.0</score>
              <method>CVSSv3</method>
              <vector>AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</vector>
            </rating>
          </ratings>
        </vulnerability>"""
    )
    sevs = parse_severities(vuln_el)
    assert len(sevs) == 1
    assert sevs[0].value == "10.0"
    assert sevs[0].scoring_elements == "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    assert sevs[0].system.identifier == "cvssv3"


def test_parse_severities_cvssv4():
    vuln_el = make_vuln_el(
        """<vulnerability>
          <ratings>
            <rating>
              <score>6.3</score>
              <method>CVSSv4</method>
              <vector>AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:L/SA:N</vector>
            </rating>
          </ratings>
        </vulnerability>"""
    )
    sevs = parse_severities(vuln_el)
    assert len(sevs) == 1
    assert sevs[0].system.identifier == "cvssv4"
    assert sevs[0].value == "6.3"


def test_parse_severities_unknown_method_skipped():
    vuln_el = make_vuln_el(
        """<vulnerability>
          <ratings>
            <rating>
              <score>5.0</score>
              <method>UNKNOWN</method>
              <vector>something</vector>
            </rating>
          </ratings>
        </vulnerability>"""
    )
    sevs = parse_severities(vuln_el)
    assert sevs == []


def test_parse_severities_no_ratings():
    vuln_el = make_vuln_el("<vulnerability></vulnerability>")
    assert parse_severities(vuln_el) == []


# --- parse_affected_packages ---


def test_parse_affected_packages_single_range():
    vuln_el = make_vuln_el(
        """<vulnerability>
          <affects>
            <target>
              <ref>pkg:maven/org.apache.logging.log4j/log4j-core?type=jar</ref>
              <versions>
                <version>
                  <range>vers:maven/&gt;=2.0-beta9|&lt;2.15.0</range>
                </version>
              </versions>
            </target>
          </affects>
        </vulnerability>"""
    )
    packages = parse_affected_packages(vuln_el)
    assert len(packages) == 1
    pkg = packages[0]
    assert pkg.package == PackageURL.from_string(
        "pkg:maven/org.apache.logging.log4j/log4j-core?type=jar"
    )
    assert ">=2.0-beta9" in str(pkg.affected_version_range)
    assert "<2.15.0" in str(pkg.affected_version_range)


def test_parse_affected_packages_multiple_ranges():
    vuln_el = make_vuln_el(
        """<vulnerability>
          <affects>
            <target>
              <ref>pkg:maven/org.apache.logging.log4j/log4j-core?type=jar</ref>
              <versions>
                <version>
                  <range>vers:maven/&gt;=2.0-beta7|&lt;2.3.1</range>
                </version>
                <version>
                  <range>vers:maven/&gt;=2.4|&lt;2.12.3</range>
                </version>
              </versions>
            </target>
          </affects>
        </vulnerability>"""
    )
    packages = parse_affected_packages(vuln_el)
    assert len(packages) == 2


def test_parse_affected_packages_no_affects():
    vuln_el = make_vuln_el("<vulnerability></vulnerability>")
    assert parse_affected_packages(vuln_el) == []


# --- parse_references ---


def test_parse_references_nvd_only():
    vuln_el = make_vuln_el(
        """<vulnerability>
          <source>
            <name>NVD</name>
            <url>https://nvd.nist.gov/vuln/detail/CVE-2021-44228</url>
          </source>
        </vulnerability>"""
    )
    refs = parse_references(vuln_el, "CVE-2021-44228")
    assert len(refs) == 1
    assert refs[0].url == "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    assert refs[0].reference_id == "CVE-2021-44228"


def test_parse_references_with_issue_tracker():
    vuln_el = make_vuln_el(
        """<vulnerability>
          <source>
            <url>https://nvd.nist.gov/vuln/detail/CVE-2020-9488</url>
          </source>
          <references>
            <reference>
              <id>LOG4J2-2819</id>
              <source>
                <url>https://issues.apache.org/jira/browse/LOG4J2-2819</url>
              </source>
            </reference>
          </references>
        </vulnerability>"""
    )
    refs = parse_references(vuln_el, "CVE-2020-9488")
    urls = [r.url for r in refs]
    assert "https://nvd.nist.gov/vuln/detail/CVE-2020-9488" in urls
    assert "https://issues.apache.org/jira/browse/LOG4J2-2819" in urls


# --- parse_advisory ---


def test_parse_advisory_cve_2021_44228():
    root = ElementTree.fromstring(SAMPLE_VDR_XML)
    vuln_el = root.find(f"{{{CDX_NS}}}vulnerabilities/{{{CDX_NS}}}vulnerability")
    advisory = parse_advisory(vuln_el)

    assert isinstance(advisory, AdvisoryDataV2)
    assert advisory.advisory_id == "CVE-2021-44228"
    assert advisory.date_published == datetime(2021, 12, 10, 0, 0, tzinfo=timezone.utc)
    assert advisory.weaknesses == [20, 400, 502, 917]
    assert len(advisory.affected_packages) == 1
    assert advisory.affected_packages[0].package.name == "log4j-core"
    assert len(advisory.severities) == 1
    assert advisory.severities[0].value == "10.0"
    assert "JNDI" in advisory.summary


def test_parse_advisory_no_id_returns_none():
    vuln_el = make_vuln_el("<vulnerability></vulnerability>")
    assert parse_advisory(vuln_el) is None


# --- Pipeline collect_advisories (mocked HTTP) ---


@pytest.fixture
def pipeline():
    return ApacheLog4jImporterPipeline()


@patch("vulnerabilities.pipelines.v2_importers.apache_log4j_importer.requests.get")
def test_collect_advisories(mock_get, pipeline):
    mock_resp = MagicMock()
    mock_resp.content = SAMPLE_VDR_XML.encode()
    mock_resp.raise_for_status = MagicMock()
    mock_get.return_value = mock_resp

    advisories = list(pipeline.collect_advisories())
    assert len(advisories) == 2
    ids = {a.advisory_id for a in advisories}
    assert "CVE-2021-44228" in ids
    assert "CVE-2025-68161" in ids


@patch("vulnerabilities.pipelines.v2_importers.apache_log4j_importer.requests.get")
def test_advisories_count(mock_get, pipeline):
    mock_resp = MagicMock()
    mock_resp.content = SAMPLE_VDR_XML.encode()
    mock_resp.raise_for_status = MagicMock()
    mock_get.return_value = mock_resp

    assert pipeline.advisories_count() == 2


@patch("vulnerabilities.pipelines.v2_importers.apache_log4j_importer.requests.get")
def test_collect_advisories_cvssv4(mock_get, pipeline):
    mock_resp = MagicMock()
    mock_resp.content = SAMPLE_VDR_XML.encode()
    mock_resp.raise_for_status = MagicMock()
    mock_get.return_value = mock_resp

    advisories = list(pipeline.collect_advisories())
    cve_2025 = next(a for a in advisories if a.advisory_id == "CVE-2025-68161")
    assert cve_2025.severities[0].system.identifier == "cvssv4"
    assert cve_2025.severities[0].value == "6.3"
    assert cve_2025.weaknesses == [297]
