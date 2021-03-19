# Copyright (c) nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import asyncio
import dataclasses
import json
import urllib
import re

import requests
from packageurl import PackageURL
from bs4 import BeautifulSoup
from dephell_specifier import RangeSpecifier
from aiohttp import ClientSession, TCPConnector

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.data_source import Reference
from vulnerabilities.package_managers import GitHubTagsAPI
from vulnerabilities.helpers import create_etag


@dataclasses.dataclass
class OpenstackDataSourceConfiguration(DataSourceConfiguration):
    etags: dict


class OpenstackDataSource(DataSource):
    CONFIG_CLASS = OpenstackDataSourceConfiguration

    url = "https://security.openstack.org/ossalist.html"

    def __enter__(self):
        self._versions = GitHubTagsAPI()
        data = requests.get(self.url).content
        self.parse_vuln_links(data)
        asyncio.run(self.crawl_vuln_links())
        packages = self.collect_packages()
        self.set_api([f'openstack/{package}' for package in packages])

    def set_api(self, packages):
        asyncio.run(self._versions.load_api(packages))

    def collect_packages(self):
        packages = set()
        PACKAGE_RE = '([A-Za-z]\w+)-*.*([A-Za-z]\w+):'
        
        for dump in self.cache['bs4_html']:
            package_str = dump.find(id='affects').find('ul').find('li').getText()
            package = re.match(PACKAGE_RE, package_str)[0][:-1]
            packages.add(package)
        return packages

    def parse_vuln_links(self, data):
        self.vuln_links = []
        soup = BeautifulSoup(data, 'lxml')
        
        vuln_list = soup.select("li.toctree-l1")
        for vuln_info in vuln_list:
            for index, child in enumerate(vuln_info.children):
                self.vuln_links.append(urllib.parse.urljoin(self.url, child.attrs['href']))
    
    async def crawl_vuln_links(self):
        self.cache = {'html': [], 'bs4_html': []}
        connector = TCPConnector(limit_per_host=15)
        async with ClientSession(raise_for_status=True, connector=connector) as session:
            await asyncio.gather(
                *[
                    self.fetch_vulnerabilities(session, endpoint)
                    for endpoint in self.vuln_links
                ]
            )
        
    async def fetch_vulnerabilities(self, session, endpoint):
        resp = await session.request(method="GET", url=endpoint)
        resptxt = await resp.text()
        self.cache['html'].append(resptxt)
        self.cache['bs4_html'].append(BeautifulSoup(resptxt, 'lxml'))


    def updated_advisories(self):
        advisories = []
        if create_etag(data_src=self, url=self.url, etag_key="ETag"):
            self.set_api()
            data = requests.get(self.url).content
            advisories.extend(self.to_advisories(data))
        return self.batch_advisories(advisories)

    
