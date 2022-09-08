#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import requests
import saneyaml
from bs4 import BeautifulSoup
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.utils import create_etag


class SUSEBackportsImporter(Importer):
    @staticmethod
    def get_all_urls_of_backports(url):
        r = requests.get(url)
        soup = BeautifulSoup(r.content, "lxml")
        for a_tag in soup.find_all("a", href=True):
            if a_tag["href"].endswith(".yaml") and a_tag["href"].startswith("backports"):
                yield url + a_tag["href"]

    def updated_advisories(self):
        advisories = []
        all_urls = self.get_all_urls_of_backports(self.config.url)
        for url in all_urls:
            if not create_etag(data_src=self, url=url, etag_key="ETag"):
                continue
            advisories.extend(self.process_file(self._fetch_yaml(url)))
        return self.batch_advisories(advisories)

    def _fetch_yaml(self, url):

        try:
            resp = requests.get(url)
            resp.raise_for_status()
            return saneyaml.load(resp.content)

        except requests.HTTPError:
            return {}

    @staticmethod
    def process_file(yaml_file):
        advisories = []
        try:
            for pkg in yaml_file[0]["packages"]:
                for version in yaml_file[0]["packages"][pkg]["fixed"]:
                    for vuln in yaml_file[0]["packages"][pkg]["fixed"][version]:
                        # yaml_file specific data can be added
                        purl = [
                            PackageURL(name=pkg, type="rpm", version=version, namespace="opensuse")
                        ]
                        advisories.append(
                            AdvisoryData(
                                vulnerability_id=vuln,
                                resolved_package_urls=purl,
                                summary="",
                                impacted_package_urls=[],
                            )
                        )
        except TypeError:
            # could've used pass
            return advisories

        return advisories
