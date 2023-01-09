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
from pathlib import Path
from typing import Iterable
from typing import List

import yaml
from bs4 import BeautifulSoup
from markdown import markdown
from packageurl import PackageURL
from univers.versions import SemverVersion

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.utils import is_cve
from vulnerabilities.utils import split_markdown_front_matter

MFSA_FILENAME_RE = re.compile(r"mfsa(\d{4}-\d{2,3})\.(md|yml)$")
logger = logging.getLogger(__name__)


class MozillaImporter(Importer):
    spdx_license_expression = "MPL-2.0"
    license_url = "https://github.com/mozilla/foundation-security-advisories/blob/master/LICENSE"
    repo_url = "git+https://github.com/mozilla/foundation-security-advisories/"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            self.clone(self.repo_url)
            path = Path(self.vcs_response.dest_dir)

            vuln = path / "announce"
            paths = list(vuln.glob("**/*.yml")) + list(vuln.glob("**/*.md"))
            for file_path in paths:
                yield from to_advisories(file_path)
        finally:
            if self.vcs_response:
                self.vcs_response.delete()


def to_advisories(path: Path) -> List[AdvisoryData]:
    """
    Convert a file to corresponding advisories.
    This calls proper method to handle yml/md files.
    """
    path = str(path)
    mfsa_id = mfsa_id_from_filename(path)
    if not mfsa_id:
        return []

    with open(path) as lines:
        if path.endswith(".md"):
            yield from get_advisories_from_md(mfsa_id, lines)
        if path.endswith(".yml"):
            yield from get_advisories_from_yml(mfsa_id, lines)

    return []


def get_advisories_from_yml(mfsa_id, lines) -> List[AdvisoryData]:
    data = yaml.safe_load(lines)
    data["mfsa_id"] = mfsa_id

    affected_packages = get_affected_packages(data.get("fixed_in") or [])
    references = get_yml_references(data)

    if not data.get("advisories"):
        return []

    for cve, advisory in data["advisories"].items():
        # These may contain HTML tags
        summary = BeautifulSoup(advisory.get("description", ""), features="lxml").get_text()
        if is_cve(cve):
            yield AdvisoryData(
                summary=summary,
                aliases=[cve],
                references=references,
                affected_packages=list(affected_packages),
            )


def get_advisories_from_md(mfsa_id, lines) -> List[AdvisoryData]:
    yamltext, mdtext = split_markdown_front_matter(lines.read())
    data = yaml.safe_load(yamltext)
    data["mfsa_id"] = mfsa_id

    affected_packages = get_affected_packages(data.get("fixed_in") or [])
    references = get_yml_references(data)
    cves = re.findall(r"CVE-\d+-\d+", yamltext + mdtext, re.IGNORECASE)
    description = html_get_p_under_h3(markdown(mdtext), "description")
    for cve in cves:
        cve_ref = Reference(
            reference_id=cve,
            url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}",
        )
        yield AdvisoryData(
            summary=description,
            aliases=[cve],
            affected_packages=list(affected_packages),
            references=references + [cve_ref],
        )


def html_get_p_under_h3(html, h3: str):
    soup = BeautifulSoup(html, features="lxml")
    h3tag = soup.find("h3", text=lambda txt: txt.lower() == h3)
    p = ""
    if h3tag:
        for tag in h3tag.next_siblings:
            if tag.name:
                if tag.name != "p":
                    break
                p += tag.get_text()
    return p


def mfsa_id_from_filename(filename):
    match = MFSA_FILENAME_RE.search(filename)
    if match:
        return "mfsa" + match.group(1)

    return None


def get_affected_packages(pkgs: List[str]) -> List[PackageURL]:
    for pkg in pkgs:
        if not pkg:
            continue
            # pkg is of the form "Firefox ESR 1.21" or "Thunderbird 2.21"
        name, _, version = pkg.rpartition(" ")
        if version and name:
            try:
                # count no of "." in version
                # if 3, then it is not a valid semver version
                if version.count(".") == 3:
                    continue
                fixed_version = SemverVersion(version)
                yield AffectedPackage(
                    package=PackageURL(
                        type="mozilla",
                        name=name,
                    ),
                    fixed_version=fixed_version,
                )
            except Exception:
                logger.exception(f"Error parsing version {version} for {name}")


def get_yml_references(data: any) -> List[Reference]:
    """
    Returns a list of references
    Currently only considers the given mfsa as a reference
    """
    # FIXME: Needs improvement
    # Should we add 'bugs' section in references too?
    # Should we add 'impact'/severity of CVE in references too?
    # If yes, then fix alpine_linux importer as well
    # Otherwise, do we need severity field for adversary as well?

    severities = ["critical", "high", "medium", "low", "none"]
    severity = "none"
    if data.get("impact"):
        impact = data.get("impact").lower()
        for s in severities:
            if s in impact:
                severity = s
                break

    return [
        Reference(
            reference_id=data["mfsa_id"],
            url="https://www.mozilla.org/en-US/security/advisories/{}".format(data["mfsa_id"]),
            severities=[VulnerabilitySeverity(system=severity_systems.GENERIC, value=severity)],
        )
    ]
