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
from typing import Tuple

from dateutil import parser as dateparser
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from pytz import UTC
from univers.version_constraint import VersionConstraint
from univers.version_range import PypiVersionRange
from univers.versions import PypiVersion

from vulnerabilities.importer import AdvisoryData
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
            cls.fetch,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def fetch(self):
        ossa_dir = Path(self.vcs_response.dest_dir) / "ossa"
        self.processable_advisories = []
        skipped_old = 0

        for file_path in sorted(ossa_dir.glob("OSSA-*.yaml")):
            data = load_yaml(str(file_path))

            date_str = data.get("date")
            date_published = dateparser.parse(str(date_str)).replace(tzinfo=UTC)
            if date_published.year < self.cutoff_year:
                skipped_old += 1
                continue

            self.processable_advisories.append(file_path)

        if skipped_old > 0:
            self.log(f"Skipped {skipped_old} advisories older than {self.cutoff_year}")
        self.log(f"Fetched {len(self.processable_advisories)} processable advisories")

    def advisories_count(self) -> int:
        return len(self.processable_advisories)

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        for file_path in self.processable_advisories:
            advisory = self.process_file(file_path)
            yield advisory

    def process_file(self, file_path) -> AdvisoryData:
        """Parse a single OSSA YAML file and extract advisory data"""
        data = load_yaml(str(file_path))
        ossa_id = data.get("id")

        date_str = data.get("date")
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
        for link in (data.get("issues")).get("links"):
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
        return AdvisoryData(
            advisory_id=ossa_id,
            aliases=aliases,
            summary=summary,
            affected_packages=affected_packages,
            references_v2=references,
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
        """
        Normalizes the version string and extracts individual constraints to create a PypiVersionRange object.
        """
        original_version_str = version_str

        if version_str.lower() == "all versions":
            self.log(f"Skipping 'all versions' - cannot parse to specific range")
            return None

        # Normalize "and" to comma
        # "<=5.0.3, >=6.0.0 <=6.1.0 and ==7.0.0" -> "<=5.0.3, >=6.0.0 <=6.1.0, ==7.0.0"
        version_str = version_str.lower().replace(" and ", ",")

        # Remove spaces around operators
        # "<=5.0.3, >=6.0.0 <=6.1.0, ==7.0.0" -> "<=5.0.3,>=6.0.0<=6.1.0,==7.0.0"
        version_str = re.sub(r"\s+([<>=!]+)", r"\1", version_str)
        version_str = re.sub(r"([<>=!]+)\s+", r"\1", version_str)

        # Insert comma between consecutive constraints
        # "<=5.0.3,>=6.0.0<=6.1.0,==7.0.0" -> "<=5.0.3,>=6.0.0,<=6.1.0,==7.0.0"
        version_str = re.sub(r"(\d)([<>=!])", r"\1,\2", version_str)

        constraints = []
        for part in version_str.split(","):
            comparator = None
            version = part

            for op in ["==", "!=", "<=", ">=", "<", ">", "="]:
                if part.startswith(op):
                    comparator = op
                    version = part[len(op) :].strip()
                    break

            # Default to "=" if no comparator is found
            # "1.16.0" -> "=1.16.0"
            if comparator is None:
                comparator = "="
            # "==27.0.0" -> "=27.0.0"
            if comparator == "==":
                comparator = "="
            try:
                constraints.append(
                    VersionConstraint(comparator=comparator, version=PypiVersion(version))
                )
            except ValueError as e:
                self.log(f"Failed to parse version '{version}' from '{original_version_str}' : {e}")
                continue

        return PypiVersionRange(constraints=constraints) if constraints else None

    def clean_downloads(self):
        if self.vcs_response:
            self.log("Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
