#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
#

import pytest
import requests
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
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

    assert len(advisories) == 1
    adv = advisories[0]
    assert isinstance(adv, AdvisoryData)
    assert adv.advisory_id == "CVE-2022-1234"


def test_unaffected_version(monkeypatch):
    html = HTML_BASE.format(affected="10.0, 10.1", fixed="10.2", summary="Issue affects all")
    monkeypatch.setattr(requests, "get", lambda url: DummyResponse(html))

    purl = PackageURL(type="generic", name="postgresql", version="10.2")
    pipeline = PostgreSQLLiveImporterPipeline(purl=purl)
    pipeline.get_purl_inputs()
    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 0


def test_qualifier_filtering(monkeypatch):
    html = HTML_BASE.format(affected="12.0, 12.1", fixed="12.2", summary="Windows-specific issue")
    monkeypatch.setattr(requests, "get", lambda url: DummyResponse(html))

    purl = PackageURL(
        type="generic", name="postgresql", version="12.1", qualifiers={"os": "windows"}
    )
    pipeline = PostgreSQLLiveImporterPipeline(purl=purl)
    pipeline.get_purl_inputs()
    advisories = list(pipeline.collect_advisories())
    assert len(advisories) == 1

    purl = PackageURL(type="generic", name="postgresql", version="12.1", qualifiers={"os": "linux"})
    pipeline = PostgreSQLLiveImporterPipeline(purl=purl)
    pipeline.get_purl_inputs()
    advisories = list(pipeline.collect_advisories())
    assert len(advisories) == 0


def test_invalid_purl():
    pipeline = PostgreSQLLiveImporterPipeline()

    pipeline.inputs = {"purl": "pkg:pypi/postgresql@10.1"}
    with pytest.raises(ValueError):
        pipeline.get_purl_inputs()

    pipeline.inputs = {"purl": "pkg:generic/notpostgresql@10.1"}
    with pytest.raises(ValueError):
        pipeline.get_purl_inputs()

    pipeline.inputs = {"purl": "pkg:generic/postgresql"}
    with pytest.raises(ValueError):
        pipeline.get_purl_inputs()
