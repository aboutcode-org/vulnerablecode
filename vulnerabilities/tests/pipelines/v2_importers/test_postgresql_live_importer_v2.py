#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#

import pytest
import requests
from packageurl import PackageURL

from vulnerabilities.pipelines.v2_importers.postgresql_live_importer import (
    PostgreSQLLiveImporterPipeline,
)

HTML_BASE = """
<html>
  <body>
    <table>
      <tbody>
        <tr>
          <td>
            <span class="nobr"><a href="/support/security/CVE-2022-1234/">CVE-2022-1234</a></span><br>
            <a href="/about/news/postgresql-175-169-1513-1418-and-1321-released-3072/">Announcement</a><br>
          </td>
          <td>{affected}</td>
          <td>{fixed}</td>
          <td><a href="/vector?vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H">9.8</a></td>
          <td>{summary}</td>
        </tr>
      </tbody>
    </table>
  </body>
</html>
"""


class DummyResponse:
    def __init__(self, content):
        self.content = content.encode("utf-8")


def test_affected_version(monkeypatch):
    html = HTML_BASE.format(affected="10.0, 10.1", fixed="10.2", summary="Issue affects all")
    monkeypatch.setattr(requests, "get", lambda url: DummyResponse(html))

    purl = PackageURL(type="generic", name="postgresql", version="10.1")
    pipeline = PostgreSQLLiveImporterPipeline(purl=purl)
    pipeline.get_purl_inputs()
    advisories = list(pipeline.collect_advisories())
    assert [adv.to_dict() for adv in advisories] == [
        {
            "advisory_id": "CVE-2022-1234",
            "affected_packages": [
                {
                    "affected_version_range": "vers:generic/10.0.0|10.1.0",
                    "fixed_by_commit_patches": [],
                    "fixed_version_range": "vers:generic/10.2.0",
                    "introduced_by_commit_patches": [],
                    "package": {
                        "name": "postgresql",
                        "namespace": "",
                        "qualifiers": "",
                        "subpath": "",
                        "type": "generic",
                        "version": "",
                    },
                }
            ],
            "aliases": [],
            "date_published": None,
            "patches": [],
            "references": [
                {
                    "reference_id": "",
                    "reference_type": "",
                    "url": "https://www.postgresql.org/support/security/CVE-2022-1234/",
                },
                {
                    "reference_id": "",
                    "reference_type": "",
                    "url": "https://www.postgresql.org/about/news/postgresql-175-169-1513-1418-and-1321-released-3072/",
                },
            ],
            "severities": [
                {
                    "scoring_elements": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "system": "cvssv3",
                    "value": "9.8",
                }
            ],
            "summary": "Issue affects all",
            "url": "https://www.postgresql.org/support/security/",
            "weaknesses": [],
        }
    ]


def test_unaffected_version(monkeypatch):
    html = HTML_BASE.format(affected="10.0, 10.1", fixed="10.2", summary="Issue affects all")
    monkeypatch.setattr(requests, "get", lambda url: DummyResponse(html))

    purl = PackageURL(type="generic", name="postgresql", version="14.3")
    pipeline = PostgreSQLLiveImporterPipeline(purl=purl)
    pipeline.get_purl_inputs()
    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 0


def test_invalid_purl():
    pipeline = PostgreSQLLiveImporterPipeline()

    pipeline.inputs = {"purl": "pkg:pypi/postgresql@10.1"}
    with pytest.raises(ValueError):
        pipeline.get_purl_inputs()
