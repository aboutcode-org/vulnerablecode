# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.
import json
import logging
from io import BytesIO
from typing import Iterable
from typing import Optional
from zipfile import ZipFile

import dateparser
import requests
from packageurl import PackageURL
from univers.version_range import InvalidVersionRange
from univers.version_range import PypiVersionRange
from univers.versions import InvalidVersion
from univers.versions import PypiVersion
from univers.versions import SemverVersion

from vulnerabilities.helpers import dedupe
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import SCORING_SYSTEMS

logger = logging.getLogger(__name__)


class PyPIImporter(Importer):
    license_url = "https://github.com/pypa/advisory-database/blob/main/LICENSE"
    spdx_license_expression = "CC-BY-4.0"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        """
        1. Fetch the data from osv api
        2. unzip the file
        3. open the file one by one
        4. yield the json file to parse_advisory_data
        """
        url = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
        response = requests.get(url).content
        with ZipFile(BytesIO(response)) as zip_file:
            for file_name in zip_file.namelist():
                if not file_name.startswith("PYSEC-"):
                    logger.error(f"NotImplementedError PyPI package file_name: {file_name}")
                else:
                    with zip_file.open(file_name) as f:
                        vul_info = json.loads(f.read())
                        yield parse_advisory_data(vul_info)


def parse_advisory_data(raw_data: dict) -> Optional[AdvisoryData]:
    raw_id = raw_data["id"]
    summary = raw_data.get("summary") or ""
    aliases = get_aliases(raw_data)
    date_published = get_published_date(raw_data)
    severity = list(get_severities(raw_data))
    references = get_references(raw_data, severity)

    affected_packages = []
    if "affected" not in raw_data:
        logger.error(f"affected_packages not found - {raw_id !r}")
        return

    for affected_pkg in raw_data.get("affected") or []:
        purl = get_affected_purl(affected_pkg, raw_id)
        if purl.type != "pypi":
            logger.error(f"Non PyPI package found in PYSEC advisories: {purl} - from: {raw_id !r}")
            continue

        affected_version_range = get_affected_version_range(affected_pkg, raw_id)
        for fixed_range in affected_pkg.get("ranges", []):
            fixed_version = get_fixed_version(fixed_range, raw_id)

            for version in fixed_version:
                affected_packages.append(
                    AffectedPackage(
                        package=purl,
                        affected_version_range=affected_version_range,
                        fixed_version=version,
                    )
                )

    return AdvisoryData(
        aliases=aliases,
        summary=summary,
        affected_packages=affected_packages,
        references=references,
        date_published=date_published,
    )


def fixed_filter(fixed_range) -> []:
    """
    Return a list of fixed version strings given a ``fixed_range`` mapping of OSV data.
    >>> list(fixed_filter({"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.6.0"}]}))
    ['1.6.0']
    >>> list(fixed_filter({"type": "ECOSYSTEM","events":[{"introduced": "0"},{"fixed": "1.0.0"},{"fixed": "9.0.0"}]}))
    ['1.0.0', '9.0.0']
    """
    for event in fixed_range.get("events") or []:
        fixed = event.get("fixed")
        if fixed:
            yield fixed


def get_aliases(raw_data) -> []:
    """
    aliases field is optional , id is required and these are all aliases from our perspective
    converting list of two fields to a dict then , convert it to a list to make sure a list is unique
    >>> get_aliases({"id": "GHSA-j3f7-7rmc-6wqj"})
    ['GHSA-j3f7-7rmc-6wqj']
    >>> get_aliases({"aliases": ["CVE-2021-40831"]})
    ['CVE-2021-40831']
    >>> get_aliases({"aliases": ["CVE-2022-22817", "GHSA-8vj2-vxx3-667w"], "id": "GHSA-j3f7-7rmc-6wqj"})
    ['CVE-2022-22817', 'GHSA-8vj2-vxx3-667w', 'GHSA-j3f7-7rmc-6wqj']
    """
    vulnerability_id = raw_data.get("id")
    vulnerability_aliases = raw_data.get("aliases") or []
    if vulnerability_id:
        vulnerability_aliases.append(vulnerability_id)
    return vulnerability_aliases


def get_published_date(raw_data):
    published = raw_data.get("published")
    return published and dateparser.parse(published)


def get_severities(raw_data) -> []:
    for sever_list in raw_data.get("severity") or []:
        if sever_list.get("type") == "CVSS_V3":
            yield VulnerabilitySeverity(
                system=SCORING_SYSTEMS["cvssv3.1_vector"], value=sever_list["score"]
            )
        else:
            logger.error(f"NotImplementedError severity type- {raw_data['id']!r}")

    ecosys = raw_data.get("ecosystem_specific") or {}
    sever = ecosys.get("severity")
    if sever:
        yield VulnerabilitySeverity(
            system=SCORING_SYSTEMS["generic_textual"],
            value=sever,
        )

    database_specific = raw_data.get("database_specific") or {}
    sever = database_specific.get("severity")
    if sever:
        yield VulnerabilitySeverity(
            system=SCORING_SYSTEMS["generic_textual"],
            value=sever,
        )


def get_references(raw_data, severities) -> []:
    references = raw_data.get("references") or []
    return [Reference(url=ref["url"], severities=severities) for ref in references if ref]


def get_affected_purl(affected_pkg, raw_id):
    package = affected_pkg.get("package") or {}
    purl = package.get("purl")
    if purl:
        try:
            return PackageURL.from_string(purl)
        except ValueError:
            logger.error(f"PackageURL ValueError - {raw_id !r} - purl: {purl !r}")

    ecosys = package.get("ecosystem")
    name = package.get("name")
    if ecosys and name:
        return PackageURL(type=ecosys, name=name)
    else:
        logger.error(f"purl affected_pkg not found - {raw_id !r}")


def get_affected_version_range(affected_pkg, raw_id):
    affected_versions = affected_pkg.get("versions")
    if affected_versions:
        try:
            return PypiVersionRange(affected_versions)
        except InvalidVersionRange:
            logger.error(f"InvalidVersionRange affected_pkg_version_range Error - {raw_id !r} ")
    else:
        logger.error(f"affected_pkg_version_range not found - {raw_id !r} ")


def get_fixed_version(fixed_range, raw_id) -> []:
    """
    Return a list of fixed versions, using fixed_filter we get the list of fixed version strings,
    then we pass every element to their univers.versions , then we dedupe the result
    >>> get_fixed_version({}, "GHSA-j3f7-7rmc-6wqj")
    []
    >>> get_fixed_version({"type": "ECOSYSTEM", "events": [{"fixed": "1.7.0"}]}, "GHSA-j3f7-7rmc-6wqj")
    [PypiVersion(string='1.7.0')]
    """
    fixed_version = []
    if "type" not in fixed_range:
        logger.error(f"Invalid type - {raw_id!r}")
    else:
        list_fixed = fixed_filter(fixed_range)
        fixed_range_type = fixed_range["type"]
        for i in list_fixed:
            if fixed_range_type == "ECOSYSTEM":
                try:
                    fixed_version.append(PypiVersion(i))
                except InvalidVersion:
                    logger.error(f"Invalid Version - PypiVersion - {raw_id !r} - {i !r}")
            if fixed_range_type == "SEMVER":
                try:
                    fixed_version.append(SemverVersion(i))
                except InvalidVersion:
                    logger.error(f"Invalid Version - SemverVersion - {raw_id !r} - {i !r}")
            if fixed_range_type == "GIT":
                # TODO add GitHubVersion univers fix_version
                logger.error(f"NotImplementedError GIT Version - {raw_id !r} - {i !r}")

    return dedupe(fixed_version)
