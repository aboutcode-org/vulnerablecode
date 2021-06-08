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
import dataclasses

import requests
import saneyaml
from bs4 import BeautifulSoup
from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.helpers import create_etag


@dataclasses.dataclass
class SUSEBackportsConfiguration(DataSourceConfiguration):
    url: str
    etags: dict


class SUSEBackportsDataSource(DataSource):

    CONFIG_CLASS = SUSEBackportsConfiguration

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
                            Advisory(
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
