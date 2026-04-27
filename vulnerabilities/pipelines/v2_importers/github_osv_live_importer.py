import json

import dateparser
import requests
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES

from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.osv_v2 import parse_advisory_data_v3
from vulnerabilities.utils import fetch_response

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
            cls.get_osv_advisories_urls,
            cls.collect_and_store_advisories,
        )

    def get_purl_inputs(self):
        purl = self.inputs.get("purl")
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
        return len(self.advisory_urls)

    def collect_advisories(self):
        """
        Fetch and parse advisory data from GitHub Advisory Database URLs, Filters the packages to
        ensure they match the exact type, name, and namespace of the target PURL, and ensure the target
        version falls within the affected or fixed version ranges and yield these related advisories
        """
        version_range = RANGE_CLASS_BY_SCHEMES.get(self.purl.type)
        version_obj = version_range.version_class(self.purl.version)
        for advisory_url in self.advisory_urls:
            response = fetch_response(advisory_url)
            raw_data = json.loads(response.content)

            advisory = parse_advisory_data_v3(
                raw_data=raw_data,
                supported_ecosystems=self.supported_types,
                advisory_url=advisory_url,
                advisory_text=json.dumps(raw_data, ensure_ascii=False),
            )

            filtered_affected_packages = [
                affected_package
                for affected_package in advisory.affected_packages
                if affected_package.package
                and affected_package.package.type == self.purl.type
                and affected_package.package.name == self.purl.name
                and (affected_package.package.namespace or "") == (self.purl.namespace or "")
            ]

            if not filtered_affected_packages:
                continue

            for affected_package in filtered_affected_packages:
                if (
                    affected_package.affected_version_range
                    and version_obj in affected_package.affected_version_range
                ) or (
                    affected_package.fixed_version_range
                    and version_obj in affected_package.fixed_version_range
                ):
                    yield advisory

    def get_osv_advisories_urls(self):
        """
        Fetch a list of OSV advisory dicts from the OSV API for a given PURL,
        filtered to only GitHub advisories (GHSA-*) and return the Advisories URLS.
        """
        ecosystem = ECOSYSTEM_BY_PURL_TYPE.get(self.purl.type)
        if not ecosystem:
            return []

        # Query by package to get all advisories for that package; we filter GHSA below.
        body = {"package": {"ecosystem": ecosystem, "name": _osv_package_name(self.purl)}}
        resp = requests.post("https://api.osv.dev/v1/query", json=body, timeout=30)
        if resp.status_code != 200:
            return []

        data = resp.json() or {}
        advisories = data.get("vulns") or []
        self.advisory_urls = set()
        for advisory in advisories:
            adv_id = advisory.get("id") or ""
            aliases = advisory.get("aliases") or []
            advisory_ids = [adv_id] + aliases
            for ghsa_id in advisory_ids:
                if not ghsa_id.startswith("GHSA-"):
                    continue

                published_date = advisory.get("published")
                advisory_url = build_github_repo_advisory_url(
                    published_date, ghsa_id, logger=self.log
                )
                self.advisory_urls.add(advisory_url)


def build_github_repo_advisory_url(published_date, advisory_id, logger):
    """
    Return the advisory JSON URL in the GitHub advisory-database repo, using the GHSA path:
    advisories/github-reviewed/YYYY/MM/GHSA-ID/GHSA-ID.json
    """
    if not published_date:
        logger(f"Cannot build URL for {advisory_id}: Missing both published and modified dates")

    parsed_date = dateparser.parse(date_string=published_date)
    year = parsed_date.strftime("%Y")
    month = parsed_date.strftime("%m")
    return f"https://raw.githubusercontent.com/github/advisory-database/refs/heads/main/advisories/github-reviewed/{year}/{month}/{advisory_id}/{advisory_id}.json"


def _osv_package_name(purl: PackageURL) -> str:
    # Maven uses groupId:artifactId, most others use namespace/name when namespace exists
    if purl.type == "maven" and purl.namespace:
        return f"{purl.namespace}:{purl.name}"
    if purl.namespace:
        return f"{purl.namespace}/{purl.name}"
    return purl.name
