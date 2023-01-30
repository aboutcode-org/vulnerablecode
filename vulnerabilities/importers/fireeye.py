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

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import GitImporter
from vulnerabilities.importer import Reference
from vulnerabilities.utils import build_description
from vulnerabilities.utils import dedupe

logger = logging.getLogger(__name__)


class FireyeImporter(GitImporter):
    spdx_license_expression = "CC-BY-SA-4.0 AND MIT"
    license_url = "https://github.com/mandiant/Vulnerability-Disclosures/blob/master/README.md"
    notice = """
    Copyright (c) Mandiant
    The following licenses/licensing apply to this Mandiant repository:
    1. CC BY-SA 4.0 - For CVE related information not including source code (such as PoCs)
    2. MIT - For source code contained within provided CVE information
    """

    def __init__(self):
        super().__init__(repo_url="git+https://github.com/mandiant/Vulnerability-Disclosures")

    def advisory_data(self) -> Iterable[AdvisoryData]:
        self.clone()
        files = filter(
            lambda p: p.suffix in [".md", ".MD"], Path(self.vcs_response.dest_dir).glob("**/*")
        )
        for file in files:
            if Path(file).stem == "README":
                continue
            try:
                with open(file) as f:
                    yield parse_advisory_data(f.read())
            except UnicodeError:
                logger.error(f"Invalid file {file}")


def parse_advisory_data(raw_data) -> AdvisoryData:
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
    impact = md_dict.get("## Impact")  # not used but can be used to get severity
    exploit_ability = md_dict.get("## Exploitability")  # not used
    cve_ref = md_dict.get("## CVE Reference") or []
    tech_details = md_dict.get("## Technical Details")  # not used
    resolution = md_dict.get("## Resolution")  # not used
    disc_credits = md_dict.get("## Discovery Credits")  # not used
    disc_timeline = md_dict.get("## Disclosure Timeline")  # not used
    references = md_dict.get("## References") or []

    return AdvisoryData(
        aliases=get_aliases(database_id, cve_ref),
        summary=build_description(" ".join(summary), " ".join(description)),
        references=get_references(references),
    )


def get_references(references):
    """
    Return a list of Reference from a list of URL reference in md format
    >>> get_references(["- http://1-4a.com/cgi-bin/alienform/af.cgi"])
    [Reference(reference_id='', url='http://1-4a.com/cgi-bin/alienform/af.cgi', severities=[])]
    >>> get_references(["- [Mitre CVE-2021-42712](https://www.cve.org/CVERecord?id=CVE-2021-42712)"])
    [Reference(reference_id='', url='https://www.cve.org/CVERecord?id=CVE-2021-42712', severities=[])]
    """
    urls = []
    for ref in references:
        if ref.startswith("- "):
            urls.append(matcher_url(ref[2::]))
        else:
            urls.append(matcher_url(ref))

    return [Reference(url=url) for url in urls if url]


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
    >>> get_aliases("MNDT-2021-0012",["CVE-2021-44207"])
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
