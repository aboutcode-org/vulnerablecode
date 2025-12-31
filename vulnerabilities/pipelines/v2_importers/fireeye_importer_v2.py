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
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.severity_systems import GENERIC
from vulnerabilities.utils import build_description
from vulnerabilities.utils import create_weaknesses_list
from vulnerabilities.utils import cwe_regex
from vulnerabilities.utils import dedupe
from vulnerabilities.utils import get_advisory_url

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
        base_path = Path(self.vcs_response.dest_dir)
        return sum(
            1
            for p in base_path.glob("**/*")
            if p.suffix.lower() == ".md" or p.stem.upper() == "README"
        )

    def clone(self):
        self.log(f"Cloning `{self.repo_url}`")
        self.vcs_response = fetch_via_vcs(self.repo_url)

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        base_path = Path(self.vcs_response.dest_dir)
        for file_path in base_path.glob("**/*"):
            if file_path.suffix.lower() != ".md":
                continue

            if file_path.stem.upper() == "README":
                continue

            try:
                with open(file_path, encoding="utf-8-sig") as f:
                    yield parse_advisory_data(
                        raw_data=f.read(), file_path=file_path, base_path=base_path
                    )
            except UnicodeError:
                logger.error(f"Invalid File UnicodeError: {file_path}")

    def clean_downloads(self):
        if self.vcs_response:
            self.log(f"Removing cloned repository")
            self.vcs_response.delete()

    def on_failure(self):
        self.clean_downloads()


def parse_advisory_data(raw_data, file_path, base_path) -> AdvisoryData:
    """
    Parse a fireeye advisory repo and return an AdvisoryData or None.
    These files are in Markdown format.
    """
    raw_data = raw_data.replace("\n\n", "\n")
    md_list = raw_data.split("\n")
    md_dict = md_list_to_dict(md_list)

    database_id = md_list[0][1::]
    summary = md_dict.get(database_id[1::]) or []
    description = md_dict.get("## Description") or []
    impact = md_dict.get("## Impact")
    cve_ids = md_dict.get("## CVE Reference") or []
    references = md_dict.get("## References") or []
    cwe_data = md_dict.get("## Common Weakness Enumeration") or []

    advisory_id = database_id.strip()
    aliases = dedupe([cve_id.strip() for cve_id in cve_ids])
    advisory_url = get_advisory_url(
        file=file_path,
        base_path=base_path,
        url="https://github.com/mandiant/Vulnerability-Disclosures/blob/master/",
    )

    return AdvisoryData(
        advisory_id=advisory_id,
        aliases=aliases,
        summary=build_description(" ".join(summary), " ".join(description)),
        references_v2=get_references(references),
        severities=get_severities(impact),
        weaknesses=get_weaknesses(cwe_data),
        url=advisory_url,
        original_advisory_text=raw_data,
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
        clean_ref = ref.strip()
        clean_ref = clean_ref.lstrip("-* ")
        url = matcher_url(clean_ref)
        if url:
            urls.append(url)
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


def get_severities(impact):
    """
    Return a list of VulnerabilitySeverity extracted from the impact string.
    >>> get_severities([
    ... "High - Arbitrary Ring 0 code execution",
    ... ])
    [VulnerabilitySeverity(system=ScoringSystem(identifier='generic_textual', name='Generic textual severity rating', url='', notes='Severity for generic scoring systems. Contains generic textual values like High, Low etc'), value='High', scoring_elements='', published_at=None, url=None)]
    >>> get_severities([])
    []
    """
    if not impact:
        return []

    impact_text = impact[0]
    value = ""
    if " - " in impact_text:
        value = impact_text.split(" - ")[0]
    elif ": " in impact_text:
        value = impact_text.split(": ")[0]
    else:
        parts = impact_text.split(" ")
        if parts:
            value = parts[0]

    if not value.lower() in ["high", "medium", "low"]:
        return []

    return [VulnerabilitySeverity(system=GENERIC, value=value)]
