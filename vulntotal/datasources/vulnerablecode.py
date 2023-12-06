#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import os
from typing import Iterable
from urllib.parse import urljoin

import requests
from dotenv import load_dotenv
from packageurl import PackageURL

from vulntotal.validator import DataSource
from vulntotal.validator import VendorData

logger = logging.getLogger(__name__)


class VulnerableCodeDataSource(DataSource):
    spdx_license_expression = "CC-BY-SA-4.0"
    license_url = "https://github.com/nexB/vulnerablecode/blob/main/cc-by-sa-4.0.LICENSE"

    global_instance = "https://public.vulnerablecode.io/"
    vc_purl_search_api_path = "api/packages/bulk_search/"

    def fetch_post_json(self, payload):
        url = urljoin(self.global_instance, self.vc_purl_search_api_path)
        response = fetch_vulnerablecode_query(url=url, payload=payload)
        if not response.status_code == 200:
            logger.error(f"Error while fetching {url}")
            return
        return response.json()

    def fetch_get_json(self, url):
        response = fetch_vulnerablecode_query(url=url, payload=None)
        if not response.status_code == 200:
            logger.error(f"Error while fetching {url}")
            return
        return response.json()

    def datasource_advisory(self, purl) -> Iterable[VendorData]:
        if purl.type not in self.supported_ecosystem() or not purl.version:
            return
        metadata_advisories = self.fetch_post_json({"purls": [str(purl)]})
        self._raw_dump.append(metadata_advisories)
        if metadata_advisories and "affected_by_vulnerabilities" in metadata_advisories[0]:
            for advisory in metadata_advisories[0]["affected_by_vulnerabilities"]:
                fetched_advisory = self.fetch_get_json(advisory["url"])
                self._raw_dump.append(fetched_advisory)
                yield parse_advisory(fetched_advisory, purl)

    @classmethod
    def supported_ecosystem(cls):
        return {
            "alpine": "alpine",
            "cargo": "cargo",
            "composer": "composer",
            "deb": "deb",
            "golang": "golang",
            "maven": "maven",
            "nginx": "nginx",
            "npm": "npm",
            "nuget": "nuget",
            "pypi": "pypi",
            "rpm": "rpm",
            "gem": "gem",
            "openssl": "openssl",
        }


def parse_advisory(fetched_advisory, purl) -> VendorData:
    aliases = [aliase["alias"] for aliase in fetched_advisory["aliases"]]
    affected_versions = []
    fixed_versions = []
    for instance in fetched_advisory["affected_packages"]:
        affected_purl = PackageURL.from_string(instance["purl"])
        if affected_purl.type == purl.type:
            affected_versions.append(affected_purl.version)
    for instance in fetched_advisory["fixed_packages"]:
        fixed_purl = PackageURL.from_string(instance["purl"])
        if fixed_purl.type == purl.type:
            fixed_versions.append(fixed_purl.version)
    return VendorData(
        purl=PackageURL(purl.type, purl.namespace, purl.name),
        aliases=aliases,
        affected_versions=affected_versions,
        fixed_versions=fixed_versions,
    )


class VCIOTokenError(Exception):
    pass


def fetch_vulnerablecode_query(url: str, payload: dict):
    """
    Requires VCIO API key in .env file
    For example::

              VCIO_TOKEN="OJ78Os2IPfM80hqVT2ek+1QnrTKvsX1HdOMABq3pmQd"
    """
    load_dotenv()
    vcio_token = os.environ.get("VCIO_TOKEN", None)
    if not vcio_token:
        msg = "Cannot call VulnerableCode API without a token set in the VCIO_TOKEN environment variable."
        raise VCIOTokenError(msg)

    response = (
        requests.post(url, headers={"Authorization": f"Token {vcio_token}"}, json=payload)
        if payload is not None
        else requests.get(url, headers={"Authorization": f"Token {vcio_token}"})
    )

    if response.text.startswith('{"detail":'):
        raise VCIOTokenError(f"{response.json().get('detail')}")

    return response
