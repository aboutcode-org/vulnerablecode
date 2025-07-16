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

import pytz
import saneyaml
from dateutil import parser
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import GitHubVersionRange
from univers.version_range import GolangVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import get_advisory_url
from vulnerabilities.utils import split_markdown_front_matter

is_release = re.compile(r"^[\d.]+$", re.IGNORECASE).match


class IstioImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Importer for Istio.io security advisories.
    """

    pipeline_id = "istio_importer_v2"
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/istio/istio.io/blob/master/LICENSE"
    repo_url = "git+https://github.com/istio/istio.io"
    unfurl_version_ranges = True

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def advisories_count(self) -> int:
        base_path = Path(self.vcs_response.dest_dir)
        advisories_dir = base_path / "content/en/news/security"
        return sum(
            1 for file in advisories_dir.rglob("*.md") if not file.name.endswith("_index.md")
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        base_path = Path(self.vcs_response.dest_dir)
        advisories_dir = base_path / "content/en/news/security"

        for md_file in advisories_dir.rglob("*.md"):
            if md_file.name.endswith("_index.md"):
                continue

            data = self.parse_markdown(md_file)
            advisory_url = get_advisory_url(
                file=md_file,
                base_path=base_path,
                url="https://github.com/istio/istio.io/blob/master/",
            )
            published_date = data.get("publishdate")
            release_date = (
                parser.parse(published_date).replace(tzinfo=pytz.UTC) if published_date else None
            )
            constraints = self.get_version_constraints(data.get("releases", []))

            cves = data.get("cves", [])

            affected_packages = []
            if constraints:
                affected_packages.extend(
                    [
                        AffectedPackage(
                            package=PackageURL(type="golang", namespace="istio.io", name="istio"),
                            affected_version_range=GolangVersionRange(constraints=constraints),
                        ),
                        AffectedPackage(
                            package=PackageURL(type="github", namespace="istio", name="istio"),
                            affected_version_range=GitHubVersionRange(constraints=constraints),
                        ),
                    ]
                )

            title = data.get("title") or ""
            summary = data.get("description") or ""
            references = []
            if title:
                references.append(
                    ReferenceV2(
                        reference_id=title,
                        url=f"https://istio.io/latest/news/security/{title}/",
                    )
                )

            yield AdvisoryData(
                advisory_id=title,
                aliases=cves,
                summary=summary,
                affected_packages=affected_packages,
                references_v2=references,
                date_published=release_date,
                url=advisory_url,
                original_advisory_text=md_file.read_text(encoding="utf-8"),
            )

    def parse_markdown(self, path: Path) -> dict:
        """Return a mapping of vulnerability data extracted from an advisory."""
        text = path.read_text(encoding="utf-8")
        front_matter, _ = split_markdown_front_matter(text)
        return saneyaml.load(front_matter)

    def get_version_constraints(self, releases: List[str]) -> List[VersionConstraint]:
        constraints = []
        for release in releases:
            release = release.strip()

            if "All releases prior" in release:
                _, _, version = release.rpartition(" ")
                constraints.append(
                    VersionConstraint(version=SemverVersion(version), comparator="<")
                )

            elif "All releases" in release and "and later" in release:
                version = release.replace("All releases", "").replace("and later", "").strip()
                if is_release(version):
                    constraints.append(
                        VersionConstraint(version=SemverVersion(version), comparator=">=")
                    )

            elif "to" in release:
                lower, _, upper = release.partition("to")
                constraints.append(
                    VersionConstraint(version=SemverVersion(lower.strip()), comparator=">=")
                )
                constraints.append(
                    VersionConstraint(version=SemverVersion(upper.strip()), comparator="<=")
                )

            elif is_release(release):
                constraints.append(
                    VersionConstraint(version=SemverVersion(release), comparator="=")
                )

        return constraints

    def clean_downloads(self):
        if self.vcs_response:
            self.log("Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()
