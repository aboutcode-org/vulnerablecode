import re
from typing import List, Tuple
import asyncio

from bs4 import BeautifulSoup
from dephell_specifier import RangeSpecifier
from packageurl import PackageURL
import requests

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import VulnerabilitySeverity
from vulnerabilities.severity_systems import scoring_systems
from vulnerabilities.package_managers import GitHubTagsAPI

SECURITY_UPDATES_URL = "https://mattermost.com/security-updates"
MM_REPO = {
    "Mattermost Mobile Apps": "mattermost/mattermost-mobile",
    "Mattermost Server": "mattermost/mattermost-server",
    "Mattermost Desktop App": "mattermost/desktop",
}


class MattermostDataSource(DataSource):
    def updated_advisories(self):
        # FIXME: Change after this https://forum.mattermost.org/t/mattermost-website-returning-403-when-headers-contain-the-word-python/11412
        self.set_api()
        data = requests.get(
            SECURITY_UPDATES_URL, headers={"user-agent": "aboutcode/vulnerablecode"}
        ).content
        return self.batch_advisories(self.to_advisories(data))

    def set_api(self):
        self.version_api = GitHubTagsAPI()
        asyncio.run(
            self.version_api.load_api(
                [
                    MM_REPO["Mattermost Mobile Apps"],
                    MM_REPO["Mattermost Server"],
                    MM_REPO["Mattermost Desktop App"],
                ]
            )
        )

    def to_advisories(self, data):
        advisories = []
        soup = BeautifulSoup(data, features="lxml")
        for row in soup.table.tbody.find_all("tr"):
            (
                ref_col,
                severity_col,
                affected_col,
                _,
                fixed_col,
                desc_col,
                name_col,
            ) = row.select("td")

            name = name_col.text.strip()
            if name not in MM_REPO:
                continue

            fixed_versions = split_versions(fixed_col.text)
            fixed_packages = [
                PackageURL(
                    type="mattermost",
                    name=name,
                    version=version,
                )
                for version in fixed_versions
            ]

            (
                affected_version_ranges,
                excluded_version_ranges,
            ) = to_affected_version_ranges(affected_col.text, fixed_col.text)

            affected_packages = [
                PackageURL(type="mattermost", name=name, version=version)
                for version in self.version_api.get(MM_REPO[name])
                if
                # The versions comparisions and advisories are not compatible with cloud-* versions
                not version.startswith("cloud-")
                and any((version in version_range for version_range in affected_version_ranges))
                and not any((version in version_range for version_range in excluded_version_ranges))
            ]

            """
            Severities are either "na" or cvssv3.1_qr
            """
            references = [
                Reference(
                    reference_id=ref_col.text,
                    url=SECURITY_UPDATES_URL,
                    severities=[
                        VulnerabilitySeverity(
                            system=scoring_systems["cvssv3.1_qr"], value=severity_col.text
                        )
                    ]
                    if severity_col.text.lower() != "na"
                    else [],
                )
            ]

            for cve_id in re.findall(r"cve-\d+-\d+", desc_col.text, re.IGNORECASE):
                references.append(
                    Reference(
                        reference_id=cve_id,
                        url=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
                    )
                )
            advisories.append(
                Advisory(
                    vulnerability_id="",
                    summary=desc_col.text,
                    references=references,
                    impacted_package_urls=affected_packages,
                    resolved_package_urls=fixed_packages,
                )
            )
        return advisories


def split_versions(versions: str) -> List[str]:
    """
    The versions can take the form:
        - v1.2,2.2 and 3.2  -> [1.2,2.2,3.2]
        - v1 and v2 -> [1,2]
        - v1, v2 -> [1,2]
        - <10 -> [<10]
        - na -> []
        - all -> all (see `affected_version_ranges`)
    Returns list of versions without leading 'v'
    """
    versions = versions.lower().strip().replace("and", ",")
    if versions == "na":
        return []
    if versions == "all":
        return ["all"]

    versions = [
        # some versions are like v2.4, remove v
        version.strip().replace("v", "")
        for version in versions.split(",")
        if version.strip()
    ]
    return versions


def to_affected_version_ranges(
    affected_col: str, fixed_col: str
) -> Tuple[List[RangeSpecifier], List[RangeSpecifier]]:
    """
    affected_col could be of type "v5.20.x to v5.26.x, excluding v5.25.5 and v5.26.2"
    fixed_col is only relevent in case affected_col is "all"
    "all" means all the versions before the only present fixed. If there are many fixed versions, it doesn't return anything.
    Needs to be improved after https://github.com/nexB/vulnerablecode/issues/119
    According to https://forum.mattermost.org/t/all-affected-versions-in-the-mattermost-advisory/11423,

    Returns affected version included_ranges, excluded_ranges
    """
    fixed_versions = split_versions(fixed_col)
    affected_col = affected_col.replace(".x", ".*")  # For 5.20.x
    included, *excluded = affected_col.split("excluding")
    range_expressions = split_versions(included)

    if len(range_expressions) == 1:
        # special cases
        if range_expressions[0] == "na":
            return [], []

        if range_expressions[0] == "all":
            if len(fixed_versions) > 1:
                # it gets very complicated. see link above
                return [], [RangeSpecifier()]
            return [RangeSpecifier(f"<{fixed_versions[0]}")], []

    included_ranges = []
    for range_expression in range_expressions:
        if "to" in range_expression:
            # eg range_expression == "3.2.0 to 3.2.1"
            lower_bound, upper_bound = range_expression.split("to")
            lower_bound = f">={lower_bound}"
            upper_bound = f"<={upper_bound}"
            included_ranges.append(RangeSpecifier(f"{lower_bound},{upper_bound}"))
        else:
            included_ranges.append(RangeSpecifier(range_expression))

    excluded_ranges = []
    if len(excluded):
        excluded_ranges = [RangeSpecifier(v) for v in split_versions(excluded[0])]

    return included_ranges, excluded_ranges
