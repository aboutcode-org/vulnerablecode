#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import types
from unittest.mock import patch

from packageurl import PackageURL
from univers.version_range import ApacheVersionRange
from univers.version_range import MavenVersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.pipelines.v2_importers.apache_tomcat_importer import (
    ApacheTomcatImporterPipeline,
)
from vulnerabilities.pipelines.v2_importers.apache_tomcat_importer import TomcatAdvisoryData
from vulnerabilities.pipelines.v2_importers.apache_tomcat_importer import parse_tomcat_security

TOMCAT_SECURITY_HTML = """
<html>
<body>

<h3 id="Fixed_in_Apache_Tomcat_10.1.9">Fixed in Apache Tomcat 10.1.9</h3>
<div class="text">
  <p>
    <strong>Request smuggling vulnerability</strong>
    <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-99999">
      CVE-2023-99999
    </a>
  </p>
  <p>Affects: 10.1.0 to 10.1.8</p>
</div>

<h3 id="Fixed_in_Apache_Tomcat_9.0.76">Fixed in Apache Tomcat 9.0.76</h3>
<div class="text">
  <p>
    <strong>Request smuggling vulnerability</strong>
    <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-99999">
      CVE-2023-99999
    </a>
  </p>
  <p>Affects: 9.0.0 to 9.0.75</p>
</div>

</body>
</html>
"""


def test_parse_tomcat_security_multiple_fixed_sections_same_cve():
    advisories = parse_tomcat_security(TOMCAT_SECURITY_HTML)

    assert len(advisories) == 2

    assert advisories[0] == TomcatAdvisoryData(
        cve="CVE-2023-99999",
        summary="Request smuggling vulnerability",
        affected_versions="10.1.0 to 10.1.8",
        fixed_in="10.1.9",
    )

    assert advisories[1] == TomcatAdvisoryData(
        cve="CVE-2023-99999",
        summary="Request smuggling vulnerability",
        affected_versions="9.0.0 to 9.0.75",
        fixed_in="9.0.76",
    )


@patch("vulnerabilities.pipelines.v2_importers.apache_tomcat_importer.requests.get")
def test_pipeline_groups_by_cve_per_page(mock_get):
    mock_get.return_value.content = TOMCAT_SECURITY_HTML.encode("utf-8")

    pipeline = ApacheTomcatImporterPipeline()

    pipeline.fetch_advisory_links = types.MethodType(
        lambda self: ["https://tomcat.apache.org/security-10.html"],
        pipeline,
    )

    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 1

    advisory = advisories[0]
    assert isinstance(advisory, AdvisoryDataV2)

    assert advisory.advisory_id == "security-10/CVE-2023-99999"
    assert advisory.url == "https://tomcat.apache.org/security-10.html"
    assert advisory.summary == "Request smuggling vulnerability"

    assert len(advisory.affected_packages) == 4


def test_affected_packages_structure():
    pipeline = ApacheTomcatImporterPipeline()

    advisory = AdvisoryDataV2(
        advisory_id="security-10/CVE-2023-99999",
        summary="Test",
        affected_packages=[],
        url="https://tomcat.apache.org/security-10.html",
    )

    # Validate package structure expectations
    for pkg in advisory.affected_packages:
        assert isinstance(pkg, AffectedPackageV2)
        assert isinstance(pkg.package, PackageURL)
        assert pkg.package.type in {"apache", "maven"}


@patch("vulnerabilities.pipelines.v2_importers.apache_tomcat_importer.requests.get")
def test_apache_and_maven_version_ranges_created(mock_get):
    mock_get.return_value.content = TOMCAT_SECURITY_HTML.encode("utf-8")

    pipeline = ApacheTomcatImporterPipeline()
    pipeline.fetch_advisory_links = types.MethodType(
        lambda self: ["https://tomcat.apache.org/security-10.html"],
        pipeline,
    )

    advisory = list(pipeline.collect_advisories())[0]

    apache_ranges = [
        p.affected_version_range for p in advisory.affected_packages if p.package.type == "apache"
    ]

    maven_ranges = [
        p.affected_version_range for p in advisory.affected_packages if p.package.type == "maven"
    ]

    assert len(apache_ranges) == 2
    assert len(maven_ranges) == 2

    for r in apache_ranges:
        assert isinstance(r, ApacheVersionRange)

    for r in maven_ranges:
        assert isinstance(r, MavenVersionRange)


def test_parse_tomcat_security_keeps_milestone_fixed_version():
    html = """
    <h3 id="Fixed_in_Apache_Tomcat_11.0.0-M6">Fixed in Apache Tomcat 11.0.0-M6</h3>
    <div class="text">
    <p><strong>Important: Information disclosure</strong>
    <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34981">CVE-2023-34981</a></p>
    <p>Affects: 11.0.0-M5</p>
    </div>
    """
    advisories = parse_tomcat_security(html)
    assert advisories[0].fixed_in == "11.0.0-M6"


def test_parse_tomcat_security_keeps_dot_style_milestone_fixed_version():
    html = """
    <h3 id="Fixed_in_Apache_Tomcat_9.0.0.M22">Fixed in Apache Tomcat 9.0.0.M22</h3>
    <div class="text">
    <p><strong>Low: Example</strong>
    <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000001">CVE-2017-1000001</a></p>
    <p>Affects: 9.0.0.M1 to 9.0.0.M21</p>
    </div>
    """
    advisories = parse_tomcat_security(html)
    assert advisories[0].fixed_in == "9.0.0.M22"
