#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Set

import pytz
import saneyaml
from dateutil import parser
from django.db.models.query import QuerySet
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import GitHubVersionRange
from univers.version_range import GolangVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import UnMergeablePackageError
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.package_managers import VersionAPI
from vulnerabilities.utils import AffectedPackage as LegacyAffectedPackage
from vulnerabilities.utils import get_affected_packages_by_patched_package
from vulnerabilities.utils import nearest_patched_package
from vulnerabilities.utils import resolve_version_range
from vulnerabilities.utils import split_markdown_front_matter

is_release = re.compile(r"^[\d.]+$", re.IGNORECASE).match

logger = logging.getLogger(__name__)


class IstioImporter(Importer):
    spdx_license_expression = "Apache-2.0"
    license_url = "https://github.com/istio/istio.io/blob/master/LICENSE"
    repo_url = "git+https://github.com/istio/istio.io/"

    def advisory_data(self) -> Set[AdvisoryData]:
        try:
            self.clone(repo_url=self.repo_url)
            path = Path(self.vcs_response.dest_dir)
            vuln = path / "content/en/news/security/"
            for file in vuln.glob("**/*.md"):
                # Istio website has files with name starting with underscore, these contain metadata
                # required for rendering the website. We're not interested in these.
                # See also https://github.com/nexB/vulnerablecode/issues/563
                file = str(file)
                if file.endswith("_index.md"):
                    continue
                yield from self.process_file(file)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()

    def process_file(self, path):

        data = self.get_data_from_md(path)
        published_date = data.get("publishdate")
        release_date = None
        if published_date:
            release_date = parser.parse(published_date).replace(tzinfo=pytz.UTC)

        constraints = []

        for release in data.get("releases") or []:
            # If it is of form "All releases prior to x"
            if "All releases prior" in release:
                _, _, release = release.strip().rpartition(" ")
                constraints.append(
                    VersionConstraint(version=SemverVersion(release), comparator="<")
                )

            # Eg. 'All releases 1.5 and later'
            elif "All releases" in release and "and later" in release:
                # remove All releases from string
                release = release.replace("All releases", "").strip()
                # remove and later from string
                release = release.replace("and later", "").strip()
                if not is_release(release):
                    continue
                constraints.append(
                    VersionConstraint(version=SemverVersion(release), comparator=">=")
                )

            # Eg. 1.5 to 2.0
            elif "to" in release:
                lower, _, upper = release.strip().partition("to")
                constraints.append(VersionConstraint(version=SemverVersion(lower), comparator=">="))
                constraints.append(VersionConstraint(version=SemverVersion(upper), comparator="<="))

            # If it is a single release
            elif is_release(release):
                constraints.append(
                    VersionConstraint(version=SemverVersion(release), comparator="=")
                )

        for cve_id in data.get("cves") or []:

            if not cve_id.startswith("CVE"):
                continue

            affected_packages = []

            if constraints:
                affected_packages.append(
                    AffectedPackage(
                        package=PackageURL(type="golang", namespace="istio.io", name="istio"),
                        affected_version_range=GolangVersionRange(constraints=constraints),
                    )
                )

                affected_packages.append(
                    AffectedPackage(
                        package=PackageURL(type="github", namespace="istio", name="istio"),
                        affected_version_range=GitHubVersionRange(constraints=constraints),
                    )
                )

            title = data.get("title") or ""
            references = []
            if title:
                references.append(
                    Reference(
                        reference_id=title,
                        url=f"https://istio.io/latest/news/security/{title}/",
                    )
                )

            summary = data.get("description") or ""

            yield AdvisoryData(
                aliases=[cve_id],
                summary=summary,
                affected_packages=affected_packages,
                references=references,
                date_published=release_date,
            )

    def get_data_from_md(self, path):
        """Return a mapping of vulnerability data extracted from an advisory."""

        with open(path) as f:
            front_matter, _ = split_markdown_front_matter(f.read())
            return saneyaml.load(front_matter)
