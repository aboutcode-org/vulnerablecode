#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging
import re
from pathlib import Path
from typing import Iterable
from typing import List

from fetchcode.vcs import fetch_via_vcs

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import build_description
from vulnerabilities.utils import create_weaknesses_list
from vulnerabilities.utils import cwe_regex
from vulnerabilities.utils import dedupe

logger = logging.getLogger(__name__)


class FireeyeImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    spdx_license_expression = "CC-BY-SA-4.0 AND MIT"
    license_url = "https://github.com/mandiant/Vulnerability-Disclosures/blob/master/README.md"
    notice = """
    Copyright (c) Mandiant
    The following licenses/licensing apply to this Mandiant repository:
    1. CC BY-SA 4.0 - For CVE related information not including source code (such as PoCs)
    2. MIT - For source code contained within provided CVE information
    """
    repo_url = "git+https://github.com/mandiant/Vulnerability-Disclosures"
    pipeline_id = "fireeye_importer_v2"

    @classmethod
    def steps(cls):
        return (
            cls.clone,
            cls.collect_and_store_advisories,
            cls.clean_downloads,
        )

    def advisories_count(self):
        files = filter(
            lambda p: p.suffix in [".md", ".MD"], Path(self.vcs_response.dest_dir).glob("**/*")
        )
        return len(list(files))

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        base_path = Path(self.vcs_response.dest_dir)
        files = filter(
            lambda p: p.suffix in [".md", ".MD"], Path(self.vcs_response.dest_dir).glob("**/*")
        )
        for file in files:
            if Path(file).stem == "README":
                continue
            try:
                with open(file, encoding="utf-8-sig") as f:
                    yield parse_advisory_data(raw_data=f.read(), file=file, base_path=base_path)
            except UnicodeError:
                logger.error(f"Invalid file {file}")

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()


def parse_advisory_data(raw_data, file, base_path) -> AdvisoryData:
    """
    Parse a fireeye advisory repo and return an AdvisoryData or None.
    These files are in Markdown format.
    """
    relative_path = str(file.relative_to(base_path)).strip("/")
    advisory_url = (
        f"https://github.com/mandiant/Vulnerability-Disclosures/blob/master/{relative_path}"
    )
    raw_data = raw_data.replace("\n\n", "\n")
    md_list = raw_data.split("\n")
    md_dict = md_list_to_dict(md_list)

    database_id = md_list[0][1::]
    summary = md_dict.get(database_id[1::]) or []
    description = md_dict.get("## Description") or []
    impact = md_dict.get("## Impact")  # not used but can be used to get severity
    exploit_ability = md_dict.get("## Exploitability")  # not used
    cve_ref = md_dict.get("## CVE Reference") or []
    tech_details = md_dict.get("## Technical Details")  # not used
    resolution = md_dict.get("## Resolution")  # not used
    disc_credits = md_dict.get("## Discovery Credits")  # not used
    disc_timeline = md_dict.get("## Disclosure Timeline")  # not used
    references = md_dict.get("## References") or []
    cwe_data = md_dict.get("## Common Weakness Enumeration") or []

    return AdvisoryData(
        advisory_id=base_path.stem,
        aliases=get_aliases(database_id, cve_ref),
        summary=build_description(" ".join(summary), " ".join(description)),
        references_v2=get_references(references),
        weaknesses=get_weaknesses(cwe_data),
        url=advisory_url,
    )


def get_references(references):
    """
    Return a list of Reference from a list of URL reference in md format
    >>> get_references(["- http://1-4a.com/cgi-bin/alienform/af.cgi"])
    [ReferenceV2(reference_id='', reference_type='', url='http://1-4a.com/cgi-bin/alienform/af.cgi')]
    >>> get_references(["- [Mitre CVE-2021-42712](https://www.cve.org/CVERecord?id=CVE-2021-42712)"])
    [ReferenceV2(reference_id='', reference_type='', url='https://www.cve.org/CVERecord?id=CVE-2021-42712')]
    """
    urls = []
    for ref in references:
        if ref.startswith("- "):
            urls.append(matcher_url(ref[2::]))
        else:
            urls.append(matcher_url(ref))

    return [ReferenceV2(url=url) for url in urls if url]


def matcher_url(ref) -> str:
    """
    Returns URL of the reference markup from reference url in Markdown format
    """
    markup_regex = "\[([^\[]+)]\(\s*(http[s]?://.+)\s*\)"
    matched_markup = re.findall(markup_regex, ref)
    if matched_markup:
        return matched_markup[0][1]
    else:
        return ref


def get_aliases(database_id, cve_ref) -> List:
    """
    Returns a List of Aliases from a database_id and a list of CVEs
    >>> get_aliases("MNDT-2021-0012", ["CVE-2021-44207"])
    ['CVE-2021-44207', 'MNDT-2021-0012']
    """
    cve_ref.append(database_id)
    return dedupe(cve_ref)


def md_list_to_dict(md_list):
    """
    Returns a dictionary of md_list from a list of a md file splited by \n
    >>> md_list_to_dict(["# Header","hello" , "hello again" ,"# Header2"])
    {'# Header': ['hello', 'hello again'], '# Header2': []}
    """
    md_dict = {}
    md_key = ""
    for md_line in md_list:
        if md_line.startswith("#"):
            md_dict[md_line] = []
            md_key = md_line
        else:
            md_dict[md_key].append(md_line)
    return md_dict


def get_weaknesses(cwe_data):
    """
    Return the list of CWE IDs as integers from a list of weakness summaries, e.g., [379].

        >>> get_weaknesses([
        ... "CWE-379: Creation of Temporary File in Directory with Insecure Permissions",
        ... "CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')"
        ... ])
        [379, 362]
    """
    cwe_list = []
    for line in cwe_data:
        cwe_ids = re.findall(cwe_regex, line)
        cwe_list.extend(cwe_ids)

    weaknesses = create_weaknesses_list(cwe_list)
    return weaknesses
