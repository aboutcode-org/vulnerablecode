from typing import Set, List, Generator

import re
import asyncio
from bs4 import BeautifulSoup
from packageurl import PackageURL
import requests

import yaml
from markdown import markdown

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import GitDataSource
from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import VulnerabilitySeverity
from vulnerabilities.severity_systems import scoring_systems
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.helpers import is_cve


REPOSITORY = "mozilla/foundation-security-advisories"
MFSA_FILENAME_RE = re.compile(r"mfsa(\d{4}-\d{2,3})\.(md|yml)$")


class MozillaDataSource(GitDataSource):
    def __enter__(self):
        super(MozillaDataSource, self).__enter__()

        if not getattr(self, "_added_files", None):
            self._added_files, self._updated_files = self.file_changes(
                recursive=True, subdir="announce"
            )

        # Do we need this ?
        # self.version_api = GitHubTagsAPI()
        # self.set_api()

    def set_api(self):
        repository = "/".join(self.config.repository_url.split("/")[-2:])
        asyncio.run(self.version_api.load_api([repository]))

    def added_advisories(self) -> Set[Advisory]:
        return self._load_advisories(self._added_files)

    def updated_advisories(self) -> Set[Advisory]:
        return self._load_advisories(self._updated_files)

    def _load_advisories(self, files) -> Set[Advisory]:
        """
        Yields list of advisories of batch size
        """
        files = [
            f for f in files if f.endswith(".md") or f.endswith(".yml")
        ]  # skip irrelevant files

        advisories = []
        for path in files:
            for advisory in self._to_advisories(path):
                advisories.append(advisory)
                if len(advisories) >= self.batch_size:
                    yield advisories
                    advisories = []

    def _to_advisories(self, path: str) -> List[Advisory]:
        """
        Convert a file to corresponding advisories.
        This calls proper method to handle yml/md files.
        """
        mfsa_id = self._mfsa_id_from_filename(path)

        with open(path) as lines:
            if path.endswith(".md"):
                return self._parse_md(mfsa_id, lines)
            elif path.endswith(".yml"):
                return self._parse_yml(mfsa_id, lines)

        return []

    def _parse_yml(self, mfsa_id, lines) -> List[Advisory]:
        advisories = []
        data = yaml.safe_load(lines)
        data["mfsa_id"] = mfsa_id

        fixed_package_urls = self._get_package_urls(data.get("fixed_in"))
        references = self._get_references(data)

        if not data.get("advisories"):
            return []

        for cve, advisory in data["advisories"].items():
            if not is_cve(cve):
                continue

            advisories.append(
                Advisory(
                    summary=advisory.get("description"),
                    vulnerability_id=cve,
                    impacted_package_urls=[],
                    resolved_package_urls=fixed_package_urls,
                    references=references,
                )
            )

        return advisories

    def _parse_md(self, mfsa_id, lines) -> List[Advisory]:
        yamltext, mdtext = self._parse_md_front_matter(lines)

        data = yaml.safe_load(yamltext)
        data["mfsa_id"] = mfsa_id

        fixed_package_urls = self._get_package_urls(data.get("fixed_in"))
        references = self._get_references(data)

        description = self._html_get_p_under_h3(markdown(mdtext), "description")

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

    def _html_get_p_under_h3(self, html, h3: str):
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

    def _parse_md_front_matter(self, lines):
        """
        Return the YAML and MD sections.
        :param: lines iterator
        :return: str YAML, str Markdown
        """
        # fm_count: 0: init, 1: in YAML, 2: in Markdown
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

        return "".join(yaml_lines), "".join(md_lines)

    def _mfsa_id_from_filename(self, filename):
        match = MFSA_FILENAME_RE.search(filename)
        if match:
            return "mfsa" + match.group(1)

        return None

    def _get_package_urls(self, pkgs: List[str]) -> List[PackageURL]:
        package_urls = [
            PackageURL(
                type="mozilla",
                # TODO: Improve after https://github.com/mozilla/foundation-security-advisories/issues/76#issuecomment-803082182
                # pkg is of the form "Firefox ESR 1.21" or "Thunderbird 2.21"
                name=" ".join(pkg.split(" ")[0:-1]),
                version=pkg.split(" ")[-1],
            )
            for pkg in pkgs
        ]
        return package_urls

    def _get_references(self, data: any) -> List[Reference]:
        """
        Returns a list of references
        Currently only considers the given mfsa as a reference
        """
        # FIXME: Needs improvement
        # Should we add 'bugs' section in references too?
        # Should we add 'impact'/severity of CVE in references too?
        # If yes, then fix alpine_linux importer as well
        # Otherwise, do we need severity field for adversary as well?

        # FIXME: Write a helper for cvssv3.1_qr severity detection ?
        severities = ["critical", "low", "high", "medium", "none"]
        severity = [{severity in data.get("impact"): severity} for severity in severities][0].get(
            True
        )

        return [
            Reference(
                reference_id=data["mfsa_id"],
                url="https://www.mozilla.org/en-US/security/advisories/{}".format(data["mfsa_id"]),
                severities=[VulnerabilitySeverity(scoring_systems["cvssv3.1_qr"], severity)],
            )
        ]
