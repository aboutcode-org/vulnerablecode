#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import tempfile
from pathlib import Path
from textwrap import dedent

import pytest
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import GitHubVersionRange
from univers.version_range import GolangVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines.v2_importers.istio_importer import IstioImporterPipeline


@pytest.mark.django_db
def test_istio_advisory_parsing():
    sample_md = dedent(
        """\
        ---
        title: ISTIO-SECURITY-2019-002
        subtitle: Security Bulletin
        description: Denial of service affecting JWT access token parsing.
        cves: [CVE-2019-12995]
        cvss: "7.5"
        vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:F/RL:O/RC:C"
        cvss_version: "3.0"
        releases: ["1.0 to 1.0.8", "1.1 to 1.1.9", "1.2 to 1.2.1"]
        publishdate: 2019-06-28
        keywords: [CVE]
        skip_seealso: true
        aliases:
            - /blog/2019/cve-2019-12995
            - /news/2019/cve-2019-12995
        ---

        A bug in Istio’s JWT validation filter causes Envoy to crash...
        """
    )

    with tempfile.TemporaryDirectory() as tmp_dir:
        base_path = Path(tmp_dir)
        advisory_dir = base_path / "content/en/news/security"
        advisory_dir.mkdir(parents=True)
        advisory_file = advisory_dir / "ISTIO-SECURITY-2019-002.md"
        advisory_file.write_text(sample_md, encoding="utf-8")

        importer = IstioImporterPipeline()
        importer.vcs_response = type(
            "FakeVCS", (), {"dest_dir": tmp_dir, "delete": lambda x: None}
        )()

        advisories = list(importer.collect_advisories())

        assert len(advisories) == 1
        advisory = advisories[0]

        assert isinstance(advisory, AdvisoryData)
        assert advisory.advisory_id == "ISTIO-SECURITY-2019-002"
        assert advisory.aliases == ["CVE-2019-12995"]
        assert advisory.summary.startswith("Denial of service affecting JWT access token")
        assert advisory.date_published.isoformat() == "2019-06-28T00:00:00+00:00"
        assert advisory.url.endswith("ISTIO-SECURITY-2019-002.md")
        assert advisory.references_v2[0] == ReferenceV2(
            reference_id="ISTIO-SECURITY-2019-002",
            url="https://istio.io/latest/news/security/ISTIO-SECURITY-2019-002/",
        )

        expected_versions = [
            VersionConstraint(version=SemverVersion("1.0"), comparator=">="),
            VersionConstraint(version=SemverVersion("1.0.8"), comparator="<="),
            VersionConstraint(version=SemverVersion("1.1"), comparator=">="),
            VersionConstraint(version=SemverVersion("1.1.9"), comparator="<="),
            VersionConstraint(version=SemverVersion("1.2"), comparator=">="),
            VersionConstraint(version=SemverVersion("1.2.1"), comparator="<="),
        ]

        expected_packages = [
            AffectedPackage(
                package=PackageURL(type="golang", namespace="istio.io", name="istio"),
                affected_version_range=GolangVersionRange(constraints=expected_versions),
            ),
            AffectedPackage(
                package=PackageURL(type="github", namespace="istio", name="istio"),
                affected_version_range=GitHubVersionRange(constraints=expected_versions),
            ),
        ]

        assert advisory.affected_packages == expected_packages
