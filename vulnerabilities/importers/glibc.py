#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from datetime import datetime
from pathlib import Path
from typing import Any
from typing import Dict
from typing import Iterable
from typing import Optional

from packageurl import PackageURL
from univers.version_range import PURL_TYPE_BY_GITLAB_SCHEME
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import VersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference


class GNUVersion(VersionRange):
    # TODO: Open PR for this in univers
    scheme = "gnu"
    version_class = SemverVersion


RANGE_CLASS_BY_SCHEMES["gnu"] = GNUVersion
PURL_TYPE_BY_GITLAB_SCHEME["gnu"] = "gnu"

RANGE_CLASS_BY_SCHEMES["gnu"] = GNUVersion


class GlibcImporter(Importer):
    repo_url = "git+https://sourceware.org/git/glibc.git"
    license_url = "https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=LICENSES"
    spdx_license_expression = "LGPL-2.1-only"
    importer_name = "Glibc Importer"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            self.vcs_response = self.clone(repo_url=self.repo_url)
            base_path = Path(self.vcs_response.dest_dir) / "advisories"
            readme_path = base_path / "README"
            files = [path for path in base_path.glob("*") if path != readme_path]
            for file in files:
                with open(file, "r") as f:
                    advisory = parse_advisory_data(f.read(), str(file.relative_to(base_path)))
                    if advisory:
                        yield advisory
        finally:
            if self.vcs_response:
                self.vcs_response.delete()


def parse_advisory_data(glibc_advisory, file_name) -> AdvisoryData:
    """
    Parses the provided GLIBC advisory data from the specified file and returns a structured representation containing the essential information.

    Args:
        glibc_advisory (str): The raw GLIBC advisory data to be parsed.
        file_name (str): The name of the file containing the advisory data.

    Returns:
        AdvisoryData: A dictionary-like object encapsulating the parsed advisory data.

    Sample Advisory:
        printf: incorrect output for integers with thousands separator and width field

        When the printf family of functions is called with a format specifier
        that uses an <apostrophe> (enable grouping) and a minimum width
        specifier, the resulting output could be larger than reasonably expected
        by a caller that computed a tight bound on the buffer size.  The
        resulting larger than expected output could result in a buffer overflow
        in the printf family of functions.

        CVE-Id: CVE-2023-25139
        Public-Date: 2023-02-02
        Vulnerable-Commit: e88b9f0e5cc50cab57a299dc7efe1a4eb385161d (2.37)
        Fix-Commit: c980549cc6a1c03c23cc2fe3e7b0fe626a0364b0 (2.38)
        Fix-Commit: 07b9521fc6369d000216b96562ff7c0ed32a16c4 (2.37-4)

    """
    content = glibc_advisory.split("\n")
    if content:
        subject = content[0]
    line_counter = 2
    description = ""
    date = ""
    cve_id = ""
    vulnerable_commits = []
    fix_commits = []
    for line in content[line_counter:]:
        if not line.strip():
            break
        description += line.strip() + " "
        line_counter += 1
    description = description.strip()
    for line in content[line_counter + 1 :]:
        if not line.strip():
            break
        tag, content = list(x.strip() for x in line.split(":"))
        match tag:
            case "CVE-Id":
                cve_id = content
            case "Public-Date":
                date = content
            case "Vulnerable-Commit":
                commit, release = content.split("(")
                release = release.strip(")").strip()
                commit = commit.strip()
                vulnerable_commits.append((commit, release))
            case "Fix-Commit":
                commit, release = content.split("(")
                release = release.strip(")").strip()
                commit = commit.strip()
                fix_commits.append((commit, release))

    advisory_dict = {
        "aliases": [cve_id],
        "affected_packages": "",
        "date_published": datetime.strptime(date, "%Y-%m-%d"),
        "summary": description,
        "references": [
            Reference(
                url="https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/" + file_name
            )
        ],
        "url": "https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=advisories/" + file_name,
    }

    purl = PackageURL(type="gnu", name="glibc")
    min_affected_version: Optional[SemverVersion, str] = ""
    max_affected_version: Optional[SemverVersion, str] = ""
    for _, release in vulnerable_commits:
        if min_affected_version == "" or max_affected_version == "":
            min_affected_version = SemverVersion(sanitize_version(release))
            max_affected_version = SemverVersion(sanitize_version(release))
        else:
            min_affected_version = (
                SemverVersion(sanitize_version(release))
                if SemverVersion(sanitize_version(release)) < min_affected_version
                else min_affected_version
            )
            max_affected_version = (
                SemverVersion(sanitize_version(release))
                if SemverVersion(sanitize_version(release)) > max_affected_version
                else max_affected_version
            )
    _, min_fixed_version = min(fix_commits, key=lambda x: SemverVersion(sanitize_version(x[1])))
    min_fixed_version = SemverVersion(sanitize_version(min_fixed_version))
    affected_version_range = None
    if max_affected_version == "" and min_affected_version == "":
        affected_version_range = None
    elif max_affected_version == min_affected_version:
        affected_version_range = VersionRange.from_string(f"vers:gnu/{str(max_affected_version)}")
    else:
        affected_version_range = VersionRange.from_string(
            f"vers:gnu/<={str(max_affected_version)}|>={min_affected_version}"
        )
    affected_packages = AffectedPackage(
        package=purl,
        affected_version_range=affected_version_range,
        fixed_version=min_fixed_version,
    )
    advisory_dict["affected_packages"] = [affected_packages]
    resolved_advisory = to_advisory(advisory_dict)
    return resolved_advisory


def sanitize_version(version: str):
    """
    Returns the version in Semver Format from Glibc Advisory

    Args:
        version (str): Version string from advisory

    Returns:
         str: Version string in Semver Format

    >>> sanitize_version('2.45-12')
    '2.45.12'
    """
    return version.replace("-", ".")


def to_advisory(advisory_data: Dict[str, Any]) -> AdvisoryData:
    """
    Returns the AdvisoryData object for a given dictionary containing advisory info

    Args:
        advisory_data: Dict[str, Any]: contains all fields to be passed to the constructor of AdvisoryData

    Returns:
        AdvisoryData: converted object into AdvisoryData format

    """
    return AdvisoryData(**advisory_data)
