#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json
import logging
from io import BytesIO
from typing import Iterable
from typing import List
from typing import Set
from zipfile import ZipFile

import dateparser
import requests

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.utils import build_description
from vulnerabilities.utils import dedupe

logger = logging.getLogger(__name__)


class GSDImporter:  # TODO inherit from Importer
    spdx_license_expression = "CC0-1.0"
    license_url = "https://github.com/cloudsecurityalliance/gsd-database/blob/main/LICENSE"
    url = "https://codeload.github.com/cloudsecurityalliance/gsd-database/zip/refs/heads/main"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        response = requests.get(self.url).content
        with ZipFile(BytesIO(response)) as zip_file:
            for file_name in zip_file.namelist():
                if file_name == "gsd-database-main/allowlist.json" or not file_name.endswith(
                    ".json"
                ):
                    continue

                with zip_file.open(file_name) as f:
                    try:
                        raw_data = json.load(f)
                        yield parse_advisory_data(raw_data, file_name)
                    except Exception as e:
                        logger.error(f"Invalid GSD advisory data file: {file_name} - {e}")


def parse_advisory_data(raw_data, file_name):
    """
    Parse a GSD advisory file and return an AdvisoryData.
    Each advisory file contains the advisory information in JSON format.
    """

    namespaces = raw_data.get("namespaces") or {}
    cve_org = namespaces.get("cve.org") or {}
    nvd_nist_gov = namespaces.get("nvd.nist.gov") or {}

    gsd = raw_data.get("GSD") or {}
    gsd_id = gsd.get("id") or file_name
    gsd_alias = gsd.get("alias") or []
    gsd_description = gsd.get("description") or ""

    gsd_reference_data = gsd.get("") or []
    gsd_references = [Reference(url=ref) for ref in gsd_reference_data]

    details = gsd_description or "".join(get_description(cve_org))

    aliases_cve_org = get_aliases(cve_org)
    aliases_nvd_nist_gov = get_aliases(nvd_nist_gov)

    aliases = [gsd_alias, gsd_id] + aliases_cve_org + aliases_nvd_nist_gov
    aliases = [alias for alias in aliases if alias is not None]

    summary = build_description(summary=get_summary(cve_org), description=details)

    severities = get_severities(cve_org)
    configurations = nvd_nist_gov.get("configurations") or {}
    nodes = configurations.get("nodes") or []
    cpes = get_cpe(nodes)

    references = get_references(cve_org) + gsd_references

    date_published = get_published_date_nvd_nist_gov(nvd_nist_gov)

    return AdvisoryData(
        aliases=dedupe(aliases),
        summary=summary,
        references=references,
        date_published=date_published,
    )


def get_summary(cve) -> str:
    """
    Returns a title of CVE_data_meta
    >> get_summary    {"CVE_data_meta": {"TITLE": "DoS vulnerability: Invalid Accent Colors"}
    'DoS vulnerability: Invalid Accent Colors'
    """
    cve_data_meta = cve.get("CVE_data_meta") or {}
    return cve_data_meta.get("TITLE") or ""


def get_severities(cve) -> List:
    """
    Return a list of CVSS vectorString
    >>> get_severities({"impact": {"cvss": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H"}}})
    ['CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H']
    """
    severities = []
    impact = cve.get("impact") or {}

    base_metric_2 = impact.get("baseMetricV2") or {}
    if base_metric_2:
        cvss_v2 = base_metric_2.get("cvssV2") or {}
        cvss_vector = cvss_v2.get("vectorString")
        if cvss_vector:
            severities.append(cvss_vector)

    base_metric_v3 = impact.get("baseMetricV3") or {}
    if base_metric_v3:
        cvss_v3 = base_metric_v3.get("cvssV3") or {}
        cvss_vector = cvss_v3.get("vectorString")
        if cvss_vector:
            severities.append(cvss_vector)

    cvss = impact.get("cvss") or {}
    if isinstance(cvss, List):
        for cvss_v in cvss:
            if isinstance(cvss_v, dict):
                cvss_vector = cvss_v.get("vectorString") or {}
                if cvss_vector:
                    severities.append(cvss_vector)
    else:
        cvss_vector = cvss.get("vectorString")
        if cvss_vector:
            severities.append(cvss_vector)
    return severities


def get_description(cve) -> [str]:
    """
    Get a list description value from description object
    >>> get_description({"description": {"description_data": [{"lang": "eng","value": "the description"}]}})
    ['the description']
    """
    description = cve.get("description") or {}
    description_data = description.get("description_data") or []
    return [desc["value"] for desc in description_data if desc["value"] and desc["lang"] == "eng"]


def get_references(cve):
    """
    Returns a list of Reference assigned with url
    >>> get_references({"references": {
    ...      "reference_data": [{
    ...            "name": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198",
    ...             "refsource": "CONFIRM",
    ...             "tags": ["Vendor Advisory"],
    ...             "url": "https://kc.mcafee.com/corporate/index?page=content&id=SB10198"}]}})
    [Reference(reference_id='', reference_type='', url='https://kc.mcafee.com/corporate/index?page=content&id=SB10198', severities=[])]
    """
    references = cve.get("references") or {}
    reference_data = references.get("reference_data") or []
    return [Reference(url=ref["url"]) for ref in reference_data if ref["url"]]


def get_aliases(cve) -> [str]:
    """
    Returns a list of aliases
    >>> get_aliases({"CVE_data_meta": {"ID": "CVE-2017-4017"},"source": {"advisory": "GHSA-v8x6-59g4-5g3w"}})
    ['CVE-2017-4017', 'GHSA-v8x6-59g4-5g3w']
    """
    cve_data_meta = cve.get("CVE_data_meta") or {}
    alias = cve_data_meta.get("ID")

    source = cve.get("source") or {}
    advisory = source.get("advisory")

    aliases = []
    if alias:
        aliases.append(alias)
    if advisory:
        aliases.append(advisory)
    return aliases


def get_published_date_nvd_nist_gov(nvd_nist_gov):
    """
    Returns a published datetime
    >>> get_published_date_nvd_nist_gov({"publishedDate": "2022-06-23T07:15Z"})
    datetime.datetime(2022, 6, 23, 7, 15, tzinfo=<StaticTzInfo 'Z'>)
    """
    published_date = nvd_nist_gov.get("publishedDate")
    return published_date and dateparser.parse(published_date)


def get_cpe(nodes) -> List:
    """
    >>> get_cpe([{"children": [], "cpe_match": [{
    ...                          "cpe23Uri": "cpe:2.3:a:mutt:mutt:*:*:*:*:*:*:*:*",
    ...                          "cpe_name": [],
    ...                          "versionEndIncluding": "1.2.5.1",
    ...                          "vulnerable": True
    ...                   },{
    ...                          "cpe23Uri": "cpe:2.3:a:mutt:mutt:*:*:*:*:*:*:*:*",
    ...                          "cpe_name": [],
    ...                          "versionEndIncluding": "1.3.25",
    ...                          "vulnerable": True
    ...                   }],"operator": "OR"}])
    ['cpe:2.3:a:mutt:mutt:*:*:*:*:*:*:*:*', 'cpe:2.3:a:mutt:mutt:*:*:*:*:*:*:*:*']
    """
    cpe_list = []
    for node in nodes:
        cpe_match = node.get("cpe_match") or []
        for cpe23Uri in cpe_match:
            cpe_uri = cpe23Uri.get("cpe23Uri")
            if cpe_uri:
                cpe_list.append(cpe_uri)
    return cpe_list
