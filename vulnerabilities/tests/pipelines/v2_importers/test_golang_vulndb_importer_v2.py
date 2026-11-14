#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
from types import SimpleNamespace

import saneyaml
from packageurl import PackageURL
from univers.versions import GolangVersion

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.pipelines.v2_importers.golang_vulndb_importer import (
    GolangVulndbImporterPipeline,
)
from vulnerabilities.pipes.univers_utils import get_exact_purls_v2

SAMPLE_OSV = {
    "schema_version": "1.3.1",
    "id": "GO-2024-2618",
    "modified": "0001-01-01T00:00:00Z",
    "published": "0001-01-01T00:00:00Z",
    "aliases": ["CVE-2024-28110", "GHSA-5pf6-2qwx-pxm2"],
    "summary": "Authentication token leak in github.com/cloudevents/sdk-go/v2",
    "details": "Using cloudevents.WithRoundTripper leaks credentials.",
    "affected": [
        {
            "package": {
                "name": "github.com/cloudevents/sdk-go/v2",
                "ecosystem": "Go",
            },
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [
                        {"introduced": "0"},
                        {"fixed": "2.15.2"},
                    ],
                }
            ],
        }
    ],
    "references": [
        {
            "type": "ADVISORY",
            "url": "https://github.com/cloudevents/sdk-go/security/advisories/GHSA-5pf6-2qwx-pxm2",
        },
        {
            "type": "FIX",
            "url": "https://github.com/cloudevents/sdk-go/commit/de2f28370b0d2a0f64f92c0c6139fa4b8a7c3851",
        },
    ],
    "database_specific": {
        "url": "https://pkg.go.dev/vuln/GO-2024-2618",
        "review_status": "REVIEWED",
    },
}

SAMPLE_STDLIB_OSV = {
    "schema_version": "1.3.1",
    "id": "GO-2021-0067",
    "published": "2021-04-14T20:04:52Z",
    "aliases": ["CVE-2021-27919"],
    "summary": "Panic when opening archives in archive/zip",
    "details": "Using Reader.Open on an archive can cause a panic.",
    "affected": [
        {
            "package": {
                "name": "stdlib",
                "ecosystem": "Go",
            },
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [
                        {"introduced": "1.16.0-0"},
                        {"fixed": "1.16.1"},
                    ],
                }
            ],
        }
    ],
    "references": [{"type": "FIX", "url": "https://go.dev/cl/300489"}],
}

SAMPLE_REPORT = {
    "id": "GO-2020-0001",
    "modules": [
        {
            "module": "github.com/gin-gonic/gin",
            "versions": [{"fixed": "1.6.0"}],
            "vulnerable_at": "1.5.0",
        }
    ],
    "summary": "Arbitrary log line injection in github.com/gin-gonic/gin",
    "description": "Unsanitized input in the default logger allows log injection.",
    "published": "2021-04-14T20:04:52Z",
    "ghsas": ["GHSA-6vm3-jj99-7229"],
    "references": [
        {"fix": "https://github.com/gin-gonic/gin/pull/2237"},
        {"fix": "https://github.com/gin-gonic/gin/commit/a71af9c144f9579f6dbe945341c1df37aaf09c0d"},
    ],
    "cve_metadata": {
        "id": "CVE-2020-36567",
        "cwe": "CWE-117 Improper Output Neutralization for Logs",
    },
}

SAMPLE_CVE5 = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.0",
    "cveMetadata": {"cveId": "CVE-2020-36567"},
    "containers": {
        "cna": {
            "title": "Arbitrary log line injection in github.com/gin-gonic/gin",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Unsanitized input in the default logger in github.com/gin-gonic/gin before v1.6.0 allows remote attackers to inject arbitrary log lines.",
                }
            ],
            "affected": [
                {
                    "packageName": "github.com/gin-gonic/gin",
                    "versions": [
                        {
                            "version": "0",
                            "lessThan": "1.6.0",
                            "status": "affected",
                            "versionType": "semver",
                        }
                    ],
                }
            ],
            "problemTypes": [
                {
                    "descriptions": [
                        {
                            "lang": "en",
                            "description": "CWE-117 Improper Output Neutralization for Logs",
                        }
                    ]
                }
            ],
            "references": [{"url": "https://pkg.go.dev/vuln/GO-2020-0001"}],
        }
    },
}


def test_clone(monkeypatch):
    import vulnerabilities.pipelines.v2_importers.golang_vulndb_importer as golang_mod

    dummy = SimpleNamespace(dest_dir="dummy", delete=lambda: None)
    monkeypatch.setattr(golang_mod, "fetch_via_vcs", lambda url: dummy)

    p = GolangVulndbImporterPipeline()
    p.clone()

    assert p.vcs_response is dummy


def test_clean_downloads_and_on_failure():
    called = {}

    def delete():
        called["deleted"] = True

    dummy = SimpleNamespace(dest_dir="dummy", delete=delete)
    p = GolangVulndbImporterPipeline()
    p.vcs_response = dummy
    p.clean_downloads()
    assert called.get("deleted", False)
    called.clear()
    p.on_failure()
    assert called.get("deleted", False)


def test_advisories_count_and_collect(tmp_path):
    osv_dir = tmp_path / "data" / "osv"
    reports_dir = tmp_path / "data" / "reports"
    cve_dir = tmp_path / "data" / "cve" / "v5"
    osv_dir.mkdir(parents=True)
    reports_dir.mkdir(parents=True)
    cve_dir.mkdir(parents=True)
    (osv_dir / "GO-2024-2618.json").write_text(json.dumps(SAMPLE_OSV))
    (osv_dir / "missing-id.json").write_text(json.dumps({"summary": "no id"}))
    (reports_dir / "GO-2020-0001.yaml").write_text(saneyaml.dump(SAMPLE_REPORT))
    (cve_dir / "GO-2020-0001.json").write_text(json.dumps(SAMPLE_CVE5))

    p = GolangVulndbImporterPipeline()
    p.vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)
    assert p.advisories_count() == 4

    advisories = list(p.collect_advisories())
    real = [a for a in advisories if isinstance(a, AdvisoryDataV2)]
    assert {a.advisory_id for a in real} == {"GO-2024-2618", "GO-2020-0001", "CVE-2020-36567"}


def test_to_advisory_data_skips_missing_id(tmp_path):
    p = GolangVulndbImporterPipeline()
    file = tmp_path / "missing.json"
    file.write_text(json.dumps({"summary": "no id"}))
    assert p.to_advisory_data(file) is None


def test_to_advisory_data_full(tmp_path):
    file = tmp_path / "GO-2024-2618.json"
    file.write_text(json.dumps(SAMPLE_OSV))
    p = GolangVulndbImporterPipeline()
    p.vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)

    adv = p.to_advisory_data(file)
    assert isinstance(adv, AdvisoryDataV2)
    assert adv.advisory_id == "GO-2024-2618"
    assert "Authentication token leak" in adv.summary
    assert adv.date_published is None
    assert adv.url == "https://pkg.go.dev/vuln/GO-2024-2618"
    assert set(adv.aliases) == {"CVE-2024-28110", "GHSA-5pf6-2qwx-pxm2"}
    urls = [r.url for r in adv.references]
    assert "https://github.com/cloudevents/sdk-go/security/advisories/GHSA-5pf6-2qwx-pxm2" in urls

    pkg = adv.affected_packages[0]
    assert pkg.package == PackageURL(
        type="golang", namespace="github.com/cloudevents/sdk-go", name="v2"
    )
    assert pkg.fixed_version_range is not None
    assert "2.15.2" in str(pkg.fixed_version_range)
    assert all(
        isinstance(constraint.version, GolangVersion)
        for constraint in pkg.fixed_version_range.constraints
    )
    affected_purls, fixed_purls = get_exact_purls_v2(pkg)
    assert [str(purl.version) for purl in fixed_purls] == ["2.15.2"]
    assert affected_purls == []


def test_to_advisory_data_stdlib_and_published_date(tmp_path):
    osv_dir = tmp_path / "data" / "osv"
    osv_dir.mkdir(parents=True)
    file = osv_dir / "GO-2021-0067.json"
    file.write_text(json.dumps(SAMPLE_STDLIB_OSV))
    p = GolangVulndbImporterPipeline()
    p.vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)

    adv = p.to_advisory_data(file)
    assert adv.advisory_id == "GO-2021-0067"
    assert adv.date_published is not None
    assert adv.date_published.year == 2021
    assert adv.affected_packages[0].package == PackageURL(type="golang", name="stdlib")
    assert adv.url.endswith("data/osv/GO-2021-0067.json")


def test_to_advisory_data_from_report(tmp_path):
    reports_dir = tmp_path / "data" / "reports"
    reports_dir.mkdir(parents=True)
    file = reports_dir / "GO-2020-0001.yaml"
    file.write_text(saneyaml.dump(SAMPLE_REPORT))
    p = GolangVulndbImporterPipeline()
    p.vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)

    adv = p.to_advisory_data_from_report(file)
    assert adv.advisory_id == "GO-2020-0001"
    assert set(adv.aliases) == {"GHSA-6vm3-jj99-7229", "CVE-2020-36567"}
    assert adv.weaknesses == [117]
    assert adv.date_published.year == 2021
    assert adv.url.endswith("data/reports/GO-2020-0001.yaml")
    urls = [r.url for r in adv.references]
    assert "https://github.com/gin-gonic/gin/pull/2237" in urls
    assert "https://pkg.go.dev/vuln/GO-2020-0001" in urls
    pkg = adv.affected_packages[0]
    assert pkg.package == PackageURL(type="golang", namespace="github.com/gin-gonic", name="gin")
    assert "1.6.0" in str(pkg.fixed_version_range)


def test_to_advisory_data_from_cve5(tmp_path):
    cve_dir = tmp_path / "data" / "cve" / "v5"
    cve_dir.mkdir(parents=True)
    file = cve_dir / "GO-2020-0001.json"
    file.write_text(json.dumps(SAMPLE_CVE5))
    p = GolangVulndbImporterPipeline()
    p.vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)

    adv = p.to_advisory_data_from_cve5(file)
    assert adv.advisory_id == "CVE-2020-36567"
    assert adv.aliases == ["GO-2020-0001"]
    assert adv.weaknesses == [117]
    assert "Unsanitized input" in adv.summary
    pkg = adv.affected_packages[0]
    assert pkg.package == PackageURL(type="golang", namespace="github.com/gin-gonic", name="gin")
    assert "1.6.0" in str(pkg.affected_version_range)
    assert "1.6.0" in str(pkg.fixed_version_range)
