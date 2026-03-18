#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path
from typing import Iterable
from typing import Tuple

from dateutil import parser as dateparser
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from pytz import UTC
from univers.version_range import InvalidVersionRange
from univers.version_range import PypiVersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import load_yaml


class OSSAImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """OpenStack Security Advisory (OSSA) Importer Pipeline V2"""

    pipeline_id = "ossa_importer_v2"
    spdx_license_expression = "CC-BY-3.0"
    license_url = "https://github.com/openstack/ossa/blob/master/LICENSE"
    repo_url = "git+https://github.com/openstack/ossa"

    # Advisories published before this year are not consumed due to inconsistent schema and irrelevance
    cutoff_year = 2016

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

    def get_processable_files(self) -> Iterable[Path]:
        """
        Returns a list of OSSA YAML files that are eligible for processing based on the cutoff year.
        """
        ossa_dir = Path(self.vcs_response.dest_dir) / "ossa"
        for file_path in sorted(ossa_dir.glob("OSSA-*.yaml")):
            filename = file_path.stem
            year = int(filename.split("-")[1])
            if year >= self.cutoff_year:
                yield file_path

    def advisories_count(self) -> int:
        return sum(1 for _ in self.get_processable_files())

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for file_path in self.get_processable_files():
            advisory = self.process_file(file_path)
            yield advisory

    def process_file(self, file_path) -> AdvisoryDataV2:
        """Parse a single OSSA YAML file and extract advisory data"""
        data = load_yaml(str(file_path))
        ossa_id = data.get("id")

        date_str = data.get("date")
        if date_str:
            date_published = dateparser.parse(str(date_str)).replace(tzinfo=UTC)

        aliases = []
        for vulnerability in data.get("vulnerabilities"):
            cve = vulnerability.get("cve-id")
            aliases.append(cve)

        affected_packages = []
        for entry in data.get("affected-products"):
            product = entry.get("product")
            version = entry.get("version")

            for package_name, version_str in self.expand_products(product, version):
                purl = PackageURL(type="pypi", name=package_name)
                version_range = self.parse_version_range(version_str)
                if purl and version_range:
                    affected_packages.append(
                        AffectedPackageV2(package=purl, affected_version_range=version_range)
                    )

        references = []
        issues = data.get("issues")
        for link in issues.get("links", []):
            references.append(ReferenceV2(url=str(link)))
        reviews = data.get("reviews")
        for branch, links in reviews.items():
            # Skip metadata fields like 'type: gerrit'(https://github.com/openstack/ossa/blob/4461806fbad5fbc111b4993b2ab4d6b718ba85c8/ossa/OSSA-2019-004.yaml#L46)
            if branch == "type":
                continue
            for link in links:
                references.append(ReferenceV2(url=link))

        title = data.get("title")
        description = data.get("description")
        summary = f"{title}\n\n{description}"
        url = f"https://security.openstack.org/ossa/{ossa_id}.html"
        return AdvisoryDataV2(
            advisory_id=ossa_id,
            aliases=aliases,
            summary=summary,
            affected_packages=affected_packages,
            references=references,
            date_published=date_published,
            url=url,
        )

    def expand_products(self, product_str, version_str) -> Iterable[Tuple[str, str]]:
        """
        OSSA advisories specifies affected products in different formats:
        Format 1:
            version="Cinder <1.0; Glance <2.0"
        Format 2:
            product="Cinder, Glance"
            version="<1.0"
        This function handles both formats and yields tuples of (product, version) for each affected product.
        """
        # Format 1: "Cinder <1.0; Glance <2.0"
        if ";" in version_str:
            for segment in version_str.split(";"):
                parts = segment.split(None, 1)
                if len(parts) == 2:
                    yield parts[0], parts[1]
            return

        # Format 2: product="Cinder, Glance"    version="<1.0"
        if "," in product_str:
            for product in product_str.split(","):
                if product:
                    yield product, version_str
            return

        yield product_str, version_str

    def parse_version_range(self, version_str: str) -> PypiVersionRange:
        """Parse a version string from OSSA advisories into a PypiVersionRange object."""

        try:
            return PypiVersionRange.from_ossa_native(version_str)
        except InvalidVersionRange as e:
            self.log(f"Failed to parse version range {version_str!r}: {e}")
            return None

    def clean_downloads(self):
        if self.vcs_response:
            self.log("Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
