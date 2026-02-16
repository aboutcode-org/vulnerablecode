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
from vulnerabilities.importer import PackageCommitPatchData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines.v2_importers.apache_tomcat_importer import (
    ApacheTomcatImporterPipeline,
    TomcatAdvisoryData,
    get_commit_patches,
    parse_tomcat_security,
)

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

TOMCAT_SECURITY_HTML_WITH_COMMITS = """
<html>
<body>
<h3 id="Fixed_in_Apache_Tomcat_10.1.40">Fixed in Apache Tomcat 10.1.40</h3>
<div class="text">
  <p>
    <strong>Important: Denial of Service</strong>
    <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-31650">CVE-2025-31650</a>
  </p>
  <p>This was fixed with commits
    <a href="https://github.com/apache/tomcat/commit/cba1a0fe1289ee7f5dd46c61c38d1e1ac5437bff">cba1a0fe</a>,
    <a href="https://github.com/apache/tomcat/commit/1eef1dc459c45f1e421d8bd25ef340fc1cc34edc">1eef1dc4</a> and
    <a href="https://github.com/apache/tomcat/commit/8cc3b8fb3f2d8d4d6a757e014f19d1fafa948a60">8cc3b8fb</a>.
  </p>
  <p>Affects: 10.1.10 to 10.1.39</p>
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


def test_parse_tomcat_security_extracts_commit_urls():
    advisories = parse_tomcat_security(TOMCAT_SECURITY_HTML_WITH_COMMITS)
    assert len(advisories) == 1
    adv = advisories[0]
    assert adv.cve == "CVE-2025-31650"
    assert len(adv.commit_urls) == 3
    assert "cba1a0fe1289ee7f5dd46c61c38d1e1ac5437bff" in adv.commit_urls[0]
    assert "1eef1dc459c45f1e421d8bd25ef340fc1cc34edc" in adv.commit_urls[1]
    assert "8cc3b8fb3f2d8d4d6a757e014f19d1fafa948a60" in adv.commit_urls[2]
    assert len(adv.reference_urls) == 3


def test_parse_tomcat_security_extracts_gitbox_commits():
    html = """
    <html><body>
    <h3 id="Fixed">Fixed 1.0</h3>
    <div class="text">
      <p><strong>Bug</strong><a href="CVE-2021-25329">CVE-2021-25329</a></p>
      <p>Fixed with commit <a href="https://gitbox.apache.org/repos/asf?p=tomcat.git;a=commit;h=7b5269715a77">7b52697</a></p>
      <p>Affects: 1.0</p>
    </div>
    </body></html>
    """
    advisories = parse_tomcat_security(html)
    assert len(advisories) == 1
    assert "7b5269715a77" in advisories[0].commit_urls[0]


def test_get_commit_patches_creates_patch_data():
    urls = [
        "https://github.com/apache/tomcat/commit/b59099e4ca501a039510334ebe1024971cd6f959",
        "https://github.com/apache/tomcat/commit/cba1a0fe1289ee7f5dd46c61c38d1e1ac5437bff",
    ]
    patches = get_commit_patches(urls)
    assert len(patches) == 2
    assert patches[0].commit_hash == "b59099e4ca501a039510334ebe1024971cd6f959"
    assert patches[0].vcs_url == "https://github.com/apache/tomcat"
    assert patches[1].commit_hash == "cba1a0fe1289ee7f5dd46c61c38d1e1ac5437bff"


@patch("vulnerabilities.pipelines.v2_importers.apache_tomcat_importer.requests.get")
def test_pipeline_populates_commit_patches_and_references(mock_get):
    mock_get.return_value.content = TOMCAT_SECURITY_HTML_WITH_COMMITS.encode("utf-8")

    pipeline = ApacheTomcatImporterPipeline()
    pipeline.fetch_advisory_links = types.MethodType(
        lambda self: ["https://tomcat.apache.org/security-10.html"],
        pipeline,
    )

    advisory = list(pipeline.collect_advisories())[0]

    assert len(advisory.affected_packages) == 2

    for pkg in advisory.affected_packages:
        assert len(pkg.fixed_by_commit_patches) == 3
        for patch in pkg.fixed_by_commit_patches:
            assert isinstance(patch, PackageCommitPatchData)
            assert patch.vcs_url == "https://github.com/apache/tomcat"

    assert len(advisory.references) == 3
    for ref in advisory.references:
        assert isinstance(ref, ReferenceV2)
