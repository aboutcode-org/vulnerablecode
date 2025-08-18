import json
from typing import Iterable
from typing import Optional

import requests
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2


class GithubOSVLiveImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    GithubOSV Live Importer Pipeline

    Collect advisories from GitHub Advisory Database for a single PURL.
    """

    pipeline_id = "github_osv_live_importer_v2"
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://github.com/github/advisory-database/blob/main/LICENSE.md"
    supported_types = ["pypi", "npm", "maven", "composer", "hex", "gem", "nuget", "cargo"]

    @classmethod
    def steps(cls):
        return (
            cls.get_purl_inputs,
            cls.collect_and_store_advisories,
        )

    def get_purl_inputs(self):
        purl = self.inputs["purl"]
        if not purl:
            raise ValueError("PURL is required for GithubOSVLiveImporterPipeline")

        if isinstance(purl, str):
            purl = PackageURL.from_string(purl)

        if not isinstance(purl, PackageURL):
            raise ValueError(f"Object of type {type(purl)} {purl!r} is not a PackageURL instance")

        if purl.type not in self.supported_types:
            raise ValueError(
                f"PURL: {purl!s} is not among the supported package types {self.supported_types!r}"
            )

        if not purl.version:
            raise ValueError(f"PURL: {purl!s} is expected to have a version")

        self.purl = purl

    def advisories_count(self):
        self.advisories = fetch_github_osv_advisories_for_purl(self.purl)
        return len(self.advisories)

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        from vulnerabilities.importers.osv import parse_advisory_data_v2

        supported_ecosystems = [
            "pypi",
            "npm",
            "maven",
            # "golang",
            "composer",
            "hex",
            "gem",
            "nuget",
            "cargo",
        ]

        input_version = self.purl.version
        vrc = RANGE_CLASS_BY_SCHEMES[self.purl.type]
        version_obj = vrc.version_class(input_version)

        for adv in self.advisories:
            adv_id = adv.get("id")
            advisory_url = build_github_repo_advisory_url(adv, adv_id)

            advisory = parse_advisory_data_v2(
                raw_data=adv,
                supported_ecosystems=supported_ecosystems,
                advisory_url=advisory_url,
                advisory_text=json.dumps(adv, ensure_ascii=False),
            )

            advisory.affected_packages = [
                ap
                for ap in advisory.affected_packages
                if ap.package
                and ap.package.type == self.purl.type
                and ap.package.name == self.purl.name
                and (ap.package.namespace or "") == (self.purl.namespace or "")
            ]

            if not advisory.affected_packages:
                continue

            if any(
                ap.affected_version_range and version_obj in ap.affected_version_range
                for ap in advisory.affected_packages
            ):
                yield advisory


ECOSYSTEM_BY_PURL_TYPE = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "composer": "Packagist",
    "hex": "Hex",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "cargo": "crates.io",
}

# Map purl.type to directory names used in the advisory-database repository
REPO_DIR_BY_PURL_TYPE = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "composer": "composer",
    "hex": "hex",
    "gem": "rubygems",
    "nuget": "nuget",
    "cargo": "crates.io",
}


def build_github_repo_advisory_url(adv: dict, adv_id: Optional[str]) -> str:
    """
    Return the advisory JSON URL in the GitHub advisory-database repo, using the GHSA path:
    advisories/github-reviewed/YYYY/MM/GHSA-ID/GHSA-ID.json
    """
    base = "https://github.com/github/advisory-database/blob/main/advisories/github-reviewed"
    if not adv_id:
        return f"{base}/"

    date_str = adv.get("published") or adv.get("modified")

    if date_str:
        from datetime import datetime

        try:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            year = dt.strftime("%Y")
            month = dt.strftime("%m")
            return f"{base}/{year}/{month}/{adv_id}/{adv_id}.json"
        except Exception:
            pass

    # Fallback to the base directory if no parseable date is present
    return f"{base}/"


def _osv_package_name(purl: PackageURL) -> str:
    # Maven uses groupId:artifactId, most others use namespace/name when namespace exists
    if purl.type == "maven" and purl.namespace:
        return f"{purl.namespace}:{purl.name}"
    if purl.namespace:
        return f"{purl.namespace}/{purl.name}"
    return purl.name


def fetch_github_osv_advisories_for_purl(purl: PackageURL):
    """
    Return a list of OSV advisory dicts from the OSV API for a given PURL,
    filtered to only GitHub advisories (GHSA-*).
    """
    ecosystem = ECOSYSTEM_BY_PURL_TYPE.get(purl.type)
    if not ecosystem:
        return []

    pkg = {"ecosystem": ecosystem, "name": _osv_package_name(purl)}
    # Query by package to get all advisories for that package; we filter GHSA below.
    body = {"package": pkg}
    try:
        resp = requests.post("https://api.osv.dev/v1/query", json=body, timeout=30)
        if resp.status_code != 200:
            return []
        data = resp.json() or {}
        vulns = data.get("vulns") or []
        # Keep only GHSA advisories which correspond to GitHub Advisory Database
        return [v for v in vulns if isinstance(v.get("id"), str) and v["id"].startswith("GHSA-")]
    except Exception:
        return []
