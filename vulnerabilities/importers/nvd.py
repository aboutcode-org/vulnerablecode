#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import gzip
import json
from datetime import date

import attr
import requests
from dateutil import parser as dateparser

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.utils import get_cwe_id
from vulnerabilities.utils import get_item


class NVDImporter(Importer):
    # See https://github.com/nexB/vulnerablecode/issues/665 for follow up
    spdx_license_expression = (
        "LicenseRef-scancode-us-govt-public-domain  AND LicenseRef-scancode-cve-tou"
    )
    license_url = "https://nvd.nist.gov/general/FAQ-Sections/General-FAQs#faqLink7"
    notice = """
    See https://nvd.nist.gov/general/FAQ-Sections/General-FAQs#faqLink7
        All NVD data is freely available from our data feeds
        (https://nvd.nist.gov/vuln/data-feeds). There are no fees, licensing
        restrictions, or even a requirement to register. All NIST publications are
        available in the public domain according to Title 17 of the United States
        Code. Acknowledgment of the NVD when using our information is appreciated.
        In addition, please email nvd@nist.gov to let us know how the information is
        being used

    See also https://cve.mitre.org/about/termsofuse.html
        Terms of Use
        LICENSE
        [...]
        CVE Usage: MITRE hereby grants you a perpetual, worldwide, non-exclusive, no-
        charge, royalty-free, irrevocable copyright license to reproduce, prepare
        derivative works of, publicly display, publicly perform, sublicense, and
        distribute Common Vulnerabilities and Exposures (CVE®). Any copy you make for
        such purposes is authorized provided that you reproduce MITRE's copyright
        designation and this license in any such copy. DISCLAIMERS

        ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN PROVIDED BY MITRE ARE
        PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE ORGANIZATION HE/SHE
        REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF
        TRUSTEES, OFFICERS, AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR
        IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE
        INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF
        MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
    """

    def advisory_data(self):
        for _year, cve_data in fetch_cve_data_1_1():
            yield from to_advisories(cve_data=cve_data)


# Isolating network calls for simplicity of testing
def fetch(url):
    gz_file = requests.get(url)
    data = gzip.decompress(gz_file.content)
    return json.loads(data)


def fetch_cve_data_1_1(starting_year=2002):
    """
    Yield tuples of (year, lists of CVE mappings) from the NVD, one for each
    year since ``starting_year`` defaulting to 2002.
    """
    current_year = date.today().year
    # NVD json feeds start from 2002.
    for year in range(starting_year, current_year + 1):
        download_url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
        yield year, fetch(url=download_url)


def to_advisories(cve_data):
    """
    Yield AdvisoryData objects from a CVE json feed.
    """
    for cve_item in CveItem.from_cve_data(cve_data=cve_data):
        if cve_item.is_related_to_hardware or not cve_item.cve_id:
            continue
        yield cve_item.to_advisory()


@attr.attributes
class CveItem:
    cve_item = attr.attrib(default=attr.Factory(dict), type=dict)

    @classmethod
    def to_advisories(cls, cve_data, skip_hardware=True):
        """
        Yield AdvisoryData objects from ``cve_data`` data for CVE JSON 1.1feed.
        Skip hardware
        """
        for cve_item in CveItem.from_cve_data(cve_data=cve_data, skip_hardware=skip_hardware):
            yield cve_item.to_advisory()

    @classmethod
    def from_cve_data(cls, cve_data, skip_hardware=True):
        """
        Yield CVE items mapping from a cve_data list of CVE mappings from the NVD.
        """
        for cve_item in cve_data.get("CVE_Items") or []:
            if not cve_item:
                continue
            if not isinstance(cve_item, dict):
                raise ValueError(f"cve_item: {cve_item!r} is not a mapping")
            cve_item = cls(cve_item=cve_item)
            if skip_hardware and cve_item.is_related_to_hardware:
                continue
            yield cve_item

    @property
    def cve_id(self):
        return self.cve_item["cve"]["CVE_data_meta"]["ID"]

    @property
    def summary(self):
        """
        Return a descriptive summary.
        """
        # In 99% of cases len(cve_item['cve']['description']['description_data']) == 1 , so
        # this usually returns  cve_item['cve']['description']['description_data'][0]['value']
        # In the remaining 1% cases this returns the longest summary.
        # FIXME: we should retun the full description WITH the summry as the first line instead
        summaries = []
        for desc in get_item(self.cve_item, "cve", "description", "description_data") or []:
            if desc.get("value"):
                summaries.append(desc["value"])
        return max(summaries, key=len) if summaries else None

    @property
    def cpes(self):
        """
        Return a list of unique CPE strings for this CVE.
        """
        # FIXME: we completely ignore the configurations here
        cpes = []
        for node in get_item(self.cve_item, "configurations", "nodes") or []:
            for cpe_data in node.get("cpe_match") or []:
                cpe23_uri = cpe_data.get("cpe23Uri")
                if cpe23_uri and cpe23_uri not in cpes:
                    cpes.append(cpe23_uri)
        return cpes

    @property
    def severities(self):
        """
        Return a list of VulnerabilitySeverity for this CVE.
        """
        severities = []
        impact = self.cve_item.get("impact") or {}
        base_metric_v3 = impact.get("baseMetricV3") or {}
        if base_metric_v3:
            cvss_v3 = get_item(base_metric_v3, "cvssV3")
            vs = VulnerabilitySeverity(
                system=severity_systems.CVSSV3,
                value=str(cvss_v3.get("baseScore") or ""),
                scoring_elements=str(cvss_v3.get("vectorString") or ""),
            )
            severities.append(vs)

        base_metric_v2 = impact.get("baseMetricV2") or {}
        if base_metric_v2:
            cvss_v2 = base_metric_v2.get("cvssV2") or {}
            vs = VulnerabilitySeverity(
                system=severity_systems.CVSSV2,
                value=str(cvss_v2.get("baseScore") or ""),
                scoring_elements=str(cvss_v2.get("vectorString") or ""),
            )
            severities.append(vs)

        return severities

    @property
    def reference_urls(self):
        """
        Return a list unique of reference URLs.
        """
        # FIXME: we should also collect additional data from the references such as tags and ids

        urls = []
        for reference in get_item(self.cve_item, "cve", "references", "reference_data") or []:
            ref_url = reference.get("url")
            if ref_url and ref_url.startswith(("http", "ftp")) and ref_url not in urls:
                urls.append(ref_url)
        return urls

    @property
    def references(self):
        """
        Return a list of AdvisoryReference.
        """
        # FIXME: we should also collect additional data from the references such as tags and ids
        references = []

        # we track each CPE as a reference for now
        for cpe in self.cpes:
            cpe_url = f"https://nvd.nist.gov/vuln/search/results?adv_search=true&isCpeNameSearch=true&query={cpe}"
            references.append(Reference(reference_id=cpe, url=cpe_url))

        # FIXME: we also add the CVE proper as a reference, but is this correct?
        references.append(
            Reference(
                url=f"https://nvd.nist.gov/vuln/detail/{self.cve_id}",
                reference_id=self.cve_id,
                severities=self.severities,
            )
        )

        # clean to remove dupes for the CVE id proper
        ref_urls = [
            ru
            for ru in self.reference_urls
            if ru != f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"
        ]
        references.extend([Reference(url=url) for url in ref_urls])

        return references

    @property
    def is_related_to_hardware(self):
        """
        Return True if this CVE item is for hardware (as opposed to software).
        """
        return any(is_related_to_hardware(cpe) for cpe in self.cpes)

    @property
    def weaknesses(self):
        """
        Return a list of CWE IDs like: [119, 189]
        """
        weaknesses = []
        for weaknesses_item in (
            get_item(self.cve_item, "cve", "problemtype", "problemtype_data") or []
        ):
            weaknesses_description = weaknesses_item.get("description") or []
            for weaknesses_value in weaknesses_description:
                cwe_id = (
                    weaknesses_value.get("value") if weaknesses_value.get("lang") == "en" else None
                )
                if cwe_id in ["NVD-CWE-Other", "NVD-CWE-noinfo"] or not cwe_id:
                    continue  # Skip Invalid CWE
                weaknesses.append(get_cwe_id(cwe_id))
        return weaknesses

    def to_advisory(self):
        """
        Return an AdvisoryData object from this CVE item
        """
        return AdvisoryData(
            aliases=[self.cve_id],
            summary=self.summary,
            references=self.references,
            date_published=dateparser.parse(self.cve_item.get("publishedDate")),
            weaknesses=self.weaknesses,
        )


def is_related_to_hardware(cpe):
    """
    Return True if the ``cpe`` is related to hardware.
    """
    cpe_comps = cpe.split(":")
    # CPE follow the format cpe:cpe_version:product_type:vendor:product
    return len(cpe_comps) > 2 and cpe_comps[2] == "h"
