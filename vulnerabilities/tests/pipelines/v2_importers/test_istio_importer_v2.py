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

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines.v2_importers.istio_importer import IstioImporterPipeline


@pytest.mark.django_db
def test_istio_advisory_parsing1():
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

        assert isinstance(advisory, AdvisoryDataV2)
        assert advisory.advisory_id == "ISTIO-SECURITY-2019-002"
        assert advisory.aliases == ["CVE-2019-12995"]
        assert advisory.summary.startswith("Denial of service affecting JWT access token")
        assert advisory.date_published.isoformat() == "2019-06-28T00:00:00+00:00"
        assert advisory.url.endswith("ISTIO-SECURITY-2019-002.md")
        assert advisory.references[0] == ReferenceV2(
            reference_id="ISTIO-SECURITY-2019-002",
            url="https://istio.io/latest/news/security/ISTIO-SECURITY-2019-002/",
        )

        assert (
            str(advisory.affected_packages[0].affected_version_range)
            == "vers:github/>=1.0.0|<=1.0.8|>=1.1.0|<=1.1.9|>=1.2.0|<=1.2.1"
        )
        assert (
            str(advisory.affected_packages[1].affected_version_range)
            == "vers:golang/>=1.0.0|<=1.0.8|>=1.1.0|<=1.1.9|>=1.2.0|<=1.2.1"
        )


@pytest.mark.django_db
def test_istio_advisory_parsing2():
    sample_md = dedent(
        """\
---
title: ISTIO-SECURITY-2021-004
subtitle: Security Bulletin
description: Potential misuse of mTLS-only fields in AuthorizationPolicy with plain text traffic. 
cves: [N/A]
cvss: "N/A"
vector: ""
releases: ["All releases 1.5 and later"]
publishdate: 2021-04-15
keywords: [CVE]
skip_seealso: true
---

{{< security_bulletin >}}

This is a security advisory for customers to check the authorization policy to make sure [mTLS (STRICT mode) is enabled](/docs/tasks/security/authentication/authn-policy/#globally-enabling-istio-mutual-tls-in-strict-mode)
when using [mTLS-only fields](/docs/concepts/security/#dependency-on-mutual-tls) in the authorization policy.
...
        """
    )

    with tempfile.TemporaryDirectory() as tmp_dir:
        base_path = Path(tmp_dir)
        advisory_dir = base_path / "content/en/news/security"
        advisory_dir.mkdir(parents=True)
        advisory_file = advisory_dir / "ISTIO-SECURITY-2021-004.md"
        advisory_file.write_text(sample_md, encoding="utf-8")

        importer = IstioImporterPipeline()
        importer.vcs_response = type(
            "FakeVCS", (), {"dest_dir": tmp_dir, "delete": lambda x: None}
        )()

        advisories = list(importer.collect_advisories())

        assert len(advisories) == 1
        advisory = advisories[0]

        assert isinstance(advisory, AdvisoryDataV2)
        assert advisory.advisory_id == "ISTIO-SECURITY-2021-004"
        assert advisory.aliases == []
        assert advisory.summary.startswith(
            "Potential misuse of mTLS-only fields in AuthorizationPolicy with plain text traffic"
        )
        assert advisory.date_published.isoformat() == "2021-04-15T00:00:00+00:00"
        assert advisory.url.endswith("ISTIO-SECURITY-2021-004.md")
