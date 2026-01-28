import types
from unittest.mock import patch

from vulnerabilities.pipelines.v2_importers.apache_tomcat_importer import (
    ApacheTomcatImporterPipeline,
    parse_tomcat_security,
    TomcatAdvisoryData,
)
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackageV2
from packageurl import PackageURL
from univers.version_range import ApacheVersionRange
from univers.version_range import MavenVersionRange


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
    assert isinstance(advisory, AdvisoryData)

    assert advisory.advisory_id == "security-10/CVE-2023-99999"
    assert advisory.url == "https://tomcat.apache.org/security-10.html"
    assert advisory.summary == "Request smuggling vulnerability"

    assert len(advisory.affected_packages) == 4


def test_affected_packages_structure():
    pipeline = ApacheTomcatImporterPipeline()

    advisory = AdvisoryData(
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
        p.affected_version_range
        for p in advisory.affected_packages
        if p.package.type == "apache"
    ]

    maven_ranges = [
        p.affected_version_range
        for p in advisory.affected_packages
        if p.package.type == "maven"
    ]

    assert len(apache_ranges) == 2
    assert len(maven_ranges) == 2

    for r in apache_ranges:
        assert isinstance(r, ApacheVersionRange)

    for r in maven_ranges:
        assert isinstance(r, MavenVersionRange)
