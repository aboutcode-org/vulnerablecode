from typing import Set, List

import re
from bs4 import BeautifulSoup
from packageurl import PackageURL
import requests

from github import Github
import yaml
from markdown import markdown

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import VulnerabilitySeverity
from vulnerabilities.severity_systems import scoring_systems
from vulnerabilities.helpers import is_cve


REPOSITORY = "mozilla/foundation-security-advisories"
MFSA_FILENAME_RE = re.compile(r"mfsa(\d{4}-\d{2,3})\.(md|yml)$")


class MozillaDataSource(DataSource):
    def updated_advisories(self) -> Set[Advisory]:
        advisories = []
        advisory_links = self.fetch_advisory_links()
        for link in advisory_links:
            advisories.extend(self.to_advisories(link))
        return self.batch_advisories(advisories)

    def fetch_advisory_links(self):
        links = []
        # TODO: Migrate to GitDataSource
        g = Github("ffa10510de8dfa1bad60cd3963c45d2db2035287")
        repo = g.get_repo(REPOSITORY)
        years = repo.get_contents("announce")
        for year in years:
            if year.type != "dir":
                continue
            advisories = repo.get_contents(year.path)
            links.extend([advisory.download_url for advisory in advisories])
        return links

    def to_advisories(self, link: str) -> Set[Advisory]:
        advisories = []

        if link.endswith(".md"):
            advisories.extend(self.parse_md(link))
        elif link.endswith(".yml"):
            advisories.extend(self.parse_yml(link))

        return advisories

    def parse_yml(self, link) -> List[Advisory]:
        advisories = []
        advisory_page = requests.get(link).text
        data = yaml.safe_load(advisory_page)

        mfsa_id = self.mfsa_id_from_filename(link)
        if mfsa_id:
            data["mfsa_id"] = mfsa_id
        else:
            ValueError("mfsa_id not present")
            # FIXME: Handle else case too? mfsa_id must be there anyway

        fixed_package_urls = self.get_package_urls(data["fixed_in"])
        references = self.get_references(data)

        for cve, advisory in data["advisories"].items():
            if not is_cve(cve):
                continue

            advisories.append(
                Advisory(
                    summary=advisory["description"],
                    vulnerability_id=cve,
                    impacted_package_urls=[],
                    resolved_package_urls=fixed_package_urls,
                    references=references,
                )
            )

        return advisories

    def parse_md(self, link) -> List[Advisory]:
        advisory_page = requests.get(link).text
        yamltext, mdtext = self.parse_md_front_matter(advisory_page)

        data = yaml.safe_load(yamltext)
        mfsa_id = self.mfsa_id_from_filename(link)
        if mfsa_id:
            data["mfsa_id"] = mfsa_id
        else:
            ValueError("mfsa_id not present")
            # FIXME: Same as parse_yml

        fixed_package_urls = self.get_package_urls(data["fixed_in"])
        references = self.get_references(data)

        soup = BeautifulSoup(markdown(mdtext), features="lxml")

        description = ""
        descTag = soup.find("h3", text=lambda txt: txt.lower() == "description")
        if descTag:
            for tag in descTag.next_siblings:
                if tag.name:
                    if tag.name != "p":
                        break
                    description += tag.get_text()

        # FIXME: add references from md ? They lack a proper reference id and are mostly bug reports

        return [
            Advisory(
                summary=description,
                vulnerability_id="",  # FIXME: Scrape the entire page for CVE regex ?
                impacted_package_urls=[],
                resolved_package_urls=fixed_package_urls,
                references=references,
            )
        ]

    def parse_md_front_matter(self, lines):
        """Return the YAML and MD sections.
        :param: lines iterator
        :return: str YAML, str Markdown
        """
        # fm_count: 0: init, 1: in YAML, 2: in Markdown
        lines = lines.split("\n")
        fm_count = 0
        yaml_lines = []
        md_lines = []
        for line in lines:
            # first line we care about is FM start
            if fm_count < 2 and line.strip() == "---":
                fm_count += 1
                continue

            if fm_count == 1:
                yaml_lines.append(line)

            if fm_count == 2:
                md_lines.append(line)

        return "\n".join(yaml_lines), "\n".join(md_lines)

    def mfsa_id_from_filename(self, filename):
        match = MFSA_FILENAME_RE.search(filename)
        if match:
            return "mfsa" + match.group(1)

        return None

    def get_package_urls(self, pkgs: List[str]) -> List[PackageURL]:
        package_urls = [
            PackageURL(
                type="mozilla",
                # TODO: Improve after https://github.com/mozilla/foundation-security-advisories/issues/76#issuecomment-803082182
                name=" ".join(pkg.split(" ")[0:-1]),
                version=pkg.split(" ")[-1],
            )
            for pkg in pkgs
        ]
        return package_urls

    def get_references(self, data: any) -> List[Reference]:
        # FIXME: Should we add 'bugs' section in references too?
        # Should we add 'impact'/severity of CVE in references too?
        # If yes, then fix alpine_linux importer as well
        # Otherwise, do we need severity fieild for adversary as well?
        return [
            Reference(
                reference_id=data["mfsa_id"],
                url="https://www.mozilla.org/en-US/security/advisories/{}".format(data["mfsa_id"]),
                severities=[
                    VulnerabilitySeverity(scoring_systems["cvssv3.1_qr"], data.get("impact"))
                ],
            )
        ]
