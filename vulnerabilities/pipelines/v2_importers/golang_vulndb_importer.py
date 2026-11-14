#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import re
from pathlib import Path
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple

import dateparser
import saneyaml
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import GolangVersionRange
from univers.versions import InvalidVersion

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.osv_v2 import parse_advisory_data_v3
from vulnerabilities.utils import build_description
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import load_json

CWE_ID_RE = re.compile(r"CWE-(\d+)", re.IGNORECASE)


class GolangVulndbImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Go Vulnerability Database importer pipeline.

    Clone https://github.com/golang/vulndb and import:
    - OSV JSON from data/osv
    - YAML reports from data/reports
    - CVE 5.0 records from data/cve/v5
    """

    pipeline_id = "golang_vulndb_importer_v2"
    datasource_id = "golang_vulndb"
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://github.com/golang/vulndb/blob/master/LICENSE"
    repo_url = "git+https://github.com/golang/vulndb"
    github_blob_base_url = "https://github.com/golang/vulndb/blob/master/"

    precedence = 500

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def _repo_root(self) -> Path:
        return Path(self.vcs_response.dest_dir)

    def _osv_dir(self) -> Path:
        return self._repo_root() / "data" / "osv"

    def _reports_dir(self) -> Path:
        return self._repo_root() / "data" / "reports"

    def _cve_v5_dir(self) -> Path:
        return self._repo_root() / "data" / "cve" / "v5"

    def advisories_count(self):
        return (
            sum(1 for _ in self._osv_dir().glob("*.json"))
            + sum(1 for _ in self._reports_dir().glob("*.yaml"))
            + sum(1 for _ in self._cve_v5_dir().glob("*.json"))
        )

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for advisory in self._osv_dir().glob("*.json"):
            yield self.to_advisory_data_from_osv(advisory)

        for advisory in self._reports_dir().glob("*.yaml"):
            yield self.to_advisory_data_from_report(advisory)

        for advisory in self._cve_v5_dir().glob("*.json"):
            yield self.to_advisory_data_from_cve5(advisory)

    def to_advisory_data(self, file: Path) -> Optional[AdvisoryDataV2]:
        return self.to_advisory_data_from_osv(file)

    def _advisory_url(self, file: Path, data: Optional[dict] = None) -> str:
        advisory_url = (data or {}).get("database_specific", {}).get("url") if data else None
        if advisory_url:
            return advisory_url
        return get_advisory_url(
            file=file,
            base_path=self._repo_root(),
            url=self.github_blob_base_url,
        )

    def to_advisory_data_from_osv(self, file: Path) -> Optional[AdvisoryDataV2]:
        data = load_json(file)
        advisory_id = data.get("id")
        if not advisory_id:
            self.log(f"Advisory ID not found in {file}")
            return

        advisory = parse_advisory_data_v3(
            raw_data=data,
            supported_ecosystems=["golang"],
            advisory_url=self._advisory_url(file, data),
            advisory_text=file.read_text(),
            advisory_id=advisory_id,
        )
        if not advisory:
            return

        # Generated OSV files sometimes use the zero date as a placeholder.
        if advisory.date_published and advisory.date_published.year < 1970:
            advisory.date_published = None
        return advisory

    def to_advisory_data_from_report(self, file: Path) -> Optional[AdvisoryDataV2]:
        advisory_text = file.read_text()
        data = saneyaml.load(advisory_text) or {}
        advisory_id = data.get("id")
        if not advisory_id:
            self.log(f"Advisory ID not found in {file}")
            return

        aliases = []
        aliases.extend(data.get("cves") or [])
        aliases.extend(data.get("ghsas") or [])
        cve_metadata = data.get("cve_metadata") or {}
        if cve_id := cve_metadata.get("id"):
            aliases.append(cve_id)
        aliases = [alias for alias in aliases if alias and alias != advisory_id]

        references = []
        for ref in data.get("references") or []:
            if isinstance(ref, dict):
                for url in ref.values():
                    if url:
                        references.append(ReferenceV2(url=url))
            elif isinstance(ref, str) and ref:
                references.append(ReferenceV2(url=ref))

        pkg_go_dev_url = f"https://pkg.go.dev/vuln/{advisory_id}"
        if pkg_go_dev_url not in [ref.url for ref in references]:
            references.append(ReferenceV2(reference_id=advisory_id, url=pkg_go_dev_url))

        weaknesses = extract_cwe_ids(cve_metadata.get("cwe") or "")
        date_published = parse_go_date(data.get("published"))

        return AdvisoryDataV2(
            advisory_id=advisory_id,
            aliases=aliases,
            summary=build_description(
                summary=data.get("summary") or "",
                description=data.get("description") or "",
            ),
            affected_packages=affected_packages_from_report(data.get("modules") or []),
            references=references,
            date_published=date_published,
            weaknesses=weaknesses,
            url=self._advisory_url(file),
            original_advisory_text=advisory_text,
        )

    def to_advisory_data_from_cve5(self, file: Path) -> Optional[AdvisoryDataV2]:
        data = load_json(file)
        cve_metadata = data.get("cveMetadata") or {}
        cve_id = cve_metadata.get("cveId")
        go_id = file.stem
        advisory_id = cve_id or go_id
        if not advisory_id:
            self.log(f"Advisory ID not found in {file}")
            return

        cna = (data.get("containers") or {}).get("cna") or {}
        summary = ""
        for description in cna.get("descriptions") or []:
            if description.get("lang") in ("en", "en-US"):
                summary = description.get("value") or ""
                break
        if not summary:
            summary = cna.get("title") or ""

        aliases = []
        if go_id and go_id != advisory_id:
            aliases.append(go_id)

        references = []
        for ref in cna.get("references") or []:
            url = ref.get("url") if isinstance(ref, dict) else ref
            if url:
                references.append(ReferenceV2(url=url))

        weaknesses = []
        for problem_type in cna.get("problemTypes") or []:
            for description in problem_type.get("descriptions") or []:
                weaknesses.extend(extract_cwe_ids(description.get("cweId") or ""))
                weaknesses.extend(extract_cwe_ids(description.get("description") or ""))
        weaknesses = sorted(set(weaknesses))

        date_published = parse_go_date(cve_metadata.get("datePublished"))

        return AdvisoryDataV2(
            advisory_id=advisory_id,
            aliases=aliases,
            summary=summary,
            affected_packages=affected_packages_from_cve5(cna.get("affected") or []),
            references=references,
            date_published=date_published,
            weaknesses=weaknesses,
            url=self._advisory_url(file),
            original_advisory_text=file.read_text(),
        )

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()


def parse_go_date(value):
    if not value or not isinstance(value, str):
        return None
    parsed = dateparser.parse(value)
    if parsed and parsed.year < 1970:
        return None
    return parsed


def extract_cwe_ids(value: str) -> List[int]:
    if not value:
        return []
    return [int(match) for match in CWE_ID_RE.findall(value)]


def golang_module_to_purl(module_path: str) -> PackageURL:
    if module_path == "std":
        module_path = "stdlib"
    purl = PackageURL(type="golang", name=module_path)
    return PackageURL.from_string(str(purl))


def golang_ranges_from_constraints(
    affected_constraints: List[VersionConstraint],
    fixed_constraints: List[VersionConstraint],
) -> Tuple[Optional[GolangVersionRange], Optional[GolangVersionRange]]:
    affected_range = None
    fixed_range = None
    if affected_constraints:
        affected_range = GolangVersionRange(
            constraints=VersionConstraint.simplify(affected_constraints)
        )
    if fixed_constraints:
        fixed_range = GolangVersionRange(constraints=VersionConstraint.simplify(fixed_constraints))
    return affected_range, fixed_range


def semver_constraint(comparator: str, version: str) -> Optional[VersionConstraint]:
    if not version or version in ("0", "*"):
        return None
    try:
        return VersionConstraint(
            comparator=comparator, version=GolangVersionRange.version_class(version)
        )
    except (InvalidVersion, ValueError, TypeError):
        return None


def affected_packages_from_report(modules: List[dict]) -> List[AffectedPackageV2]:
    affected_packages = []
    for module in modules:
        module_path = module.get("module")
        if not module_path:
            continue

        affected_constraints = []
        fixed_constraints = []
        for version in module.get("versions") or []:
            introduced = semver_constraint(">=", version.get("introduced"))
            if introduced:
                affected_constraints.append(introduced)
            fixed = version.get("fixed")
            if fixed_lt := semver_constraint("<", fixed):
                affected_constraints.append(fixed_lt)
            if fixed_eq := semver_constraint("=", fixed):
                fixed_constraints.append(fixed_eq)

        affected_range, fixed_range = golang_ranges_from_constraints(
            affected_constraints, fixed_constraints
        )
        if not affected_range and not fixed_range:
            continue

        try:
            affected_packages.append(
                AffectedPackageV2(
                    package=golang_module_to_purl(module_path),
                    affected_version_range=affected_range,
                    fixed_version_range=fixed_range,
                )
            )
        except Exception:
            continue
    return affected_packages


def affected_packages_from_cve5(affected: List[dict]) -> List[AffectedPackageV2]:
    affected_packages = []
    for item in affected:
        module_path = item.get("packageName") or item.get("product")
        if not module_path:
            continue

        affected_constraints = []
        fixed_constraints = []
        for version in item.get("versions") or []:
            if version.get("status") not in (None, "affected"):
                continue
            introduced = semver_constraint(">=", version.get("version"))
            if introduced:
                affected_constraints.append(introduced)
            if less_than := semver_constraint("<", version.get("lessThan")):
                affected_constraints.append(less_than)
                if fixed_eq := semver_constraint("=", version.get("lessThan")):
                    fixed_constraints.append(fixed_eq)
            if less_equal := semver_constraint("<=", version.get("lessThanOrEqual")):
                affected_constraints.append(less_equal)

        affected_range, fixed_range = golang_ranges_from_constraints(
            affected_constraints, fixed_constraints
        )
        if not affected_range and not fixed_range:
            continue

        try:
            affected_packages.append(
                AffectedPackageV2(
                    package=golang_module_to_purl(module_path),
                    affected_version_range=affected_range,
                    fixed_version_range=fixed_range,
                )
            )
        except Exception:
            continue
    return affected_packages
