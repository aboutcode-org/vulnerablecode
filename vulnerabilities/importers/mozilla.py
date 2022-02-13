import re
from typing import List
from typing import Set

import yaml
from bs4 import BeautifulSoup
from markdown import markdown
from packageurl import PackageURL

from vulnerabilities.helpers import is_cve
from vulnerabilities.helpers import split_markdown_front_matter
from vulnerabilities.importer import Advisory
from vulnerabilities.importer import GitImporter
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import SCORING_SYSTEMS

REPOSITORY = "mozilla/foundation-security-advisories"
MFSA_FILENAME_RE = re.compile(r"mfsa(\d{4}-\d{2,3})\.(md|yml)$")


class MozillaImporter(GitImporter):
    def __enter__(self):
        super(MozillaImporter, self).__enter__()

        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, subdir="announce"
            )

    def updated_advisories(self) -> Set[Advisory]:
        files = self._updated_files.union(self._added_files)
        files = [
            f for f in files if f.endswith(".md") or f.endswith(".yml")
        ]  # skip irrelevant files

        advisories = []
        for path in files:
            advisories.extend(to_advisories(path))

        return self.batch_advisories(advisories)


def to_advisories(path: str) -> List[Advisory]:
    """
    Convert a file to corresponding advisories.
    This calls proper method to handle yml/md files.
    """
    mfsa_id = mfsa_id_from_filename(path)
    if not mfsa_id:
        return []

    with open(path) as lines:
        if path.endswith(".md"):
            return get_advisories_from_md(mfsa_id, lines)
        if path.endswith(".yml"):
            return get_advisories_from_yml(mfsa_id, lines)

    return []


def get_advisories_from_yml(mfsa_id, lines) -> List[Advisory]:
    advisories = []
    data = yaml.safe_load(lines)
    data["mfsa_id"] = mfsa_id

    fixed_package_urls = get_package_urls(data.get("fixed_in"))
    references = get_yml_references(data)

    if not data.get("advisories"):
        return []

    for cve, advisory in data["advisories"].items():
        # These may contain HTML tags
        summary = BeautifulSoup(advisory.get("description", ""), features="lxml").get_text()

        advisories.append(
            Advisory(
                summary=summary,
                vulnerability_id=cve if is_cve(cve) else "",
                impacted_package_urls=[],
                resolved_package_urls=fixed_package_urls,
                references=references,
            )
        )

    return advisories


def get_advisories_from_md(mfsa_id, lines) -> List[Advisory]:
    yamltext, mdtext = split_markdown_front_matter(lines.read())
    data = yaml.safe_load(yamltext)
    data["mfsa_id"] = mfsa_id

    fixed_package_urls = get_package_urls(data.get("fixed_in"))
    references = get_yml_references(data)
    cves = re.findall(r"CVE-\d+-\d+", yamltext + mdtext, re.IGNORECASE)
    for cve in cves:
        references.append(
            Reference(
                reference_id=cve,
                url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}",
            )
        )

    description = html_get_p_under_h3(markdown(mdtext), "description")

    return [
        Advisory(
            summary=description,
            vulnerability_id="",
            impacted_package_urls=[],
            resolved_package_urls=fixed_package_urls,
            references=references,
        )
    ]


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


def get_package_urls(pkgs: List[str]) -> List[PackageURL]:
    package_urls = [
        PackageURL(
            type="mozilla",
            # pkg is of the form "Firefox ESR 1.21" or "Thunderbird 2.21"
            name=pkg.rsplit(None, 1)[0],
            version=pkg.rsplit(None, 1)[1],
        )
        for pkg in pkgs
        if pkg
    ]
    return package_urls


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
            severities=[VulnerabilitySeverity(scoring_systems["generic_textual"], severity)],
        )
    ]
