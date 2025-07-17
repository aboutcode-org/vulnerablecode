#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock
from unittest.mock import patch

import pytz
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import NpmVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.pipelines.v2_importers.npm_importer import NpmImporterPipeline
from vulnerabilities.severity_systems import CVSSV2
from vulnerabilities.severity_systems import CVSSV3

TEST_DATA = Path(__file__).parent.parent / "test_data" / "npm"


def test_clone(monkeypatch):
    import vulnerabilities.pipelines.v2_importers.npm_importer as npm_mod

    dummy = SimpleNamespace(dest_dir="dummy", delete=lambda: None)
    # Patch the name in the npm_importer module, not fetchcode.vcs
    monkeypatch.setattr(npm_mod, "fetch_via_vcs", lambda url: dummy)

    p = NpmImporterPipeline()
    p.clone()

    assert p.vcs_response is dummy


def test_clean_downloads_and_on_failure():
    called = {}

    def delete():
        called["deleted"] = True

    dummy = SimpleNamespace(dest_dir="dummy", delete=delete)
    p = NpmImporterPipeline()
    p.vcs_response = dummy
    p.clean_downloads()
    assert called.get("deleted", False)
    called.clear()
    p.on_failure()
    assert called.get("deleted", False)


def test_advisories_count_and_collect(tmp_path):
    base = tmp_path
    vuln_dir = base / "vuln" / "npm"
    vuln_dir.mkdir(parents=True)
    (vuln_dir / "index.json").write_text("{}")
    (vuln_dir / "001.json").write_text(json.dumps({"id": "001"}))
    p = NpmImporterPipeline()
    p.vcs_response = SimpleNamespace(dest_dir=str(base), delete=lambda: None)
    advisories = list(p.collect_advisories())
    assert p.advisories_count() == 2
    # Should yield None for index.json and one AdvisoryData
    real = [a for a in advisories if isinstance(a, AdvisoryData)]
    assert len(real) == 1
    assert real[0].advisory_id == "npm-001"


def test_to_advisory_data_skips_index(tmp_path):
    p = NpmImporterPipeline()
    file = tmp_path / "index.json"
    file.write_text("{}")
    assert p.to_advisory_data(file) is None


def test_to_advisory_data_full(tmp_path):
    data = {
        "id": "123",
        "overview": "desc",
        "title": "ti",
        "created_at": "2021-01-01T00:00:00Z",
        "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": "9.8",
        "references": ["http://ref1"],
        "module_name": "mypkg",
        "vulnerable_versions": "<=1.2.3",
        "patched_versions": ">=1.2.4",
        "cves": ["CVE-123", "CVE-124"],
    }
    file = tmp_path / "123.json"
    file.write_text(json.dumps(data))
    p = NpmImporterPipeline()
    adv = p.to_advisory_data(file)
    assert isinstance(adv, AdvisoryData)
    assert adv.advisory_id == "npm-123"
    assert "ti" in adv.summary and "desc" in adv.summary
    assert adv.date_published.tzinfo == pytz.UTC
    assert len(adv.severities) == 1 and adv.severities[0].system == CVSSV3
    urls = [r.url for r in adv.references_v2]
    assert "http://ref1" in urls
    assert f"https://github.com/nodejs/security-wg/blob/main/vuln/npm/123.json" in urls
    pkg = adv.affected_packages[0]
    assert pkg.package == PackageURL(type="npm", name="mypkg")
    assert isinstance(pkg.affected_version_range, NpmVersionRange)
    assert pkg.fixed_version == SemverVersion("1.2.4")
    assert set(adv.aliases) == {"CVE-123", "CVE-124"}


def test_to_advisory_data_cvss_v2(tmp_path):
    data = {"id": "124", "cvss_vector": "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", "cvss_score": "5.5"}
    file = tmp_path / "124.json"
    file.write_text(json.dumps(data))
    p = NpmImporterPipeline()
    adv = p.to_advisory_data(file)
    assert len(adv.severities) == 1 and adv.severities[0].system == CVSSV2


def test_get_affected_package_special_and_standard():
    p = NpmImporterPipeline()
    pkg = p.get_affected_package(
        {"vulnerable_versions": "<=99.999.99999", "patched_versions": "<0.0.0"}, "pkg"
    )
    assert isinstance(pkg.affected_version_range, NpmVersionRange)
    assert pkg.fixed_version is None
    data2 = {"vulnerable_versions": "<=2.0.0", "patched_versions": ">=2.0.1"}
    pkg2 = p.get_affected_package(data2, "pkg2")
    assert isinstance(pkg2.affected_version_range, NpmVersionRange)
    assert pkg2.fixed_version == SemverVersion("2.0.1")


def test_package_first_mode_valid_npm_package(tmp_path):
    vuln_dir = tmp_path / "vuln" / "npm"
    vuln_dir.mkdir(parents=True)

    npm_sample_file = os.path.join(TEST_DATA, "npm_sample.json")
    with open(npm_sample_file) as f:
        sample_data = json.load(f)

    advisory_file = vuln_dir / "152.json"
    advisory_file.write_text(json.dumps(sample_data))

    mock_vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)

    purl = PackageURL(type="npm", name="npm", version="1.2.0")
    pipeline = NpmImporterPipeline(purl=purl)
    pipeline.vcs_response = mock_vcs_response

    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 1
    assert advisories[0].aliases == ["CVE-2013-4116"]
    assert len(advisories[0].affected_packages) == 1
    assert advisories[0].affected_packages[0].package.name == "npm"


def test_package_first_mode_unaffected_version(tmp_path):
    vuln_dir = tmp_path / "vuln" / "npm"
    vuln_dir.mkdir(parents=True)

    npm_sample_file = os.path.join(TEST_DATA, "npm_sample.json")
    with open(npm_sample_file) as f:
        sample_data = json.load(f)

    advisory_file = vuln_dir / "152.json"
    advisory_file.write_text(json.dumps(sample_data))

    mock_vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)

    purl = PackageURL(type="npm", name="npm", version="1.4.0")
    pipeline = NpmImporterPipeline(purl=purl)
    pipeline.vcs_response = mock_vcs_response

    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 0


def test_package_first_mode_invalid_package_type(tmp_path):
    vuln_dir = tmp_path / "vuln" / "npm"
    vuln_dir.mkdir(parents=True)

    mock_vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)

    purl = PackageURL(type="pypi", name="django", version="3.0.0")
    pipeline = NpmImporterPipeline(purl=purl)
    pipeline.vcs_response = mock_vcs_response

    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 0


def test_package_first_mode_package_not_found(tmp_path):
    vuln_dir = tmp_path / "vuln" / "npm"
    vuln_dir.mkdir(parents=True)

    npm_sample_file = os.path.join(TEST_DATA, "npm_sample.json")
    with open(npm_sample_file) as f:
        sample_data = json.load(f)

    sample_data["module_name"] = "some-other-package"

    advisory_file = vuln_dir / "152.json"
    advisory_file.write_text(json.dumps(sample_data))

    mock_vcs_response = SimpleNamespace(dest_dir=str(tmp_path), delete=lambda: None)

    purl = PackageURL(type="npm", name="nonexistent-package", version="1.0.0")
    pipeline = NpmImporterPipeline(purl=purl)
    pipeline.vcs_response = mock_vcs_response

    advisories = list(pipeline.collect_advisories())

    assert len(advisories) == 0


def test_version_is_affected():
    purl = PackageURL(type="npm", name="npm", version="1.2.0")
    pipeline = NpmImporterPipeline(purl=purl)

    affected_package = AffectedPackage(
        package=PackageURL(type="npm", name="npm"),
        affected_version_range=NpmVersionRange(
            constraints=(VersionConstraint(comparator="<", version=SemverVersion(string="1.3.3")),)
        ),
    )

    assert pipeline._version_is_affected(affected_package) == True

    pipeline.purl = PackageURL(type="npm", name="npm", version="1.4.0")
    assert pipeline._version_is_affected(affected_package) == False

    pipeline.purl = PackageURL(type="npm", name="npm")
    assert pipeline._version_is_affected(affected_package) == True

    affected_package_no_range = AffectedPackage(
        package=PackageURL(type="npm", name="npm"),
        affected_version_range=None,
        fixed_version=SemverVersion(string="1.3.3"),
    )
    assert pipeline._version_is_affected(affected_package_no_range) == True
