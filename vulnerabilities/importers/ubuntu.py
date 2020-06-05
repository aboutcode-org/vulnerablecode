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


import asyncio
import bz2
import dataclasses
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Set
import xml.etree.ElementTree as ET


from aiohttp import ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientResponseError
import requests
from packageurl import PackageURL


from vulnerabilities.data_source import OvalDataSource, DataSourceConfiguration, Advisory


@dataclasses.dataclass
class UbuntuConfiguration(DataSourceConfiguration):
    releases: list


class UbuntuDataSource(OvalDataSource):

    CONFIG_CLASS = UbuntuConfiguration

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we could avoid setting translations, and have it
        # set by default in the OvalParser, but we don't yet know
        # whether all OVAL providers use the same format
        self.translations = {'less than': '<'}
        self.pkg_manager_api = VersionAPI()

    def _fetch(self):
        base_url = 'https://people.canonical.com/~ubuntu-security/oval/'
        file_name = 'com.ubuntu.{}.cve.oval.xml.bz2'
        releases = self.config.releases
        for release in releases:
            print("getting ", release)
            resp = requests.get(base_url + file_name.format(release))
            extracted = bz2.decompress(resp.content)
            print("done ")
            yield ({'type': 'deb'}, ET.ElementTree(ET.fromstring(extracted.decode('utf-8'))))

    def set_api(self, packages):
        asyncio.run(self.pkg_manager_api.load_api(packages))


class VersionAPI:
    def __init__(self, cache: Mapping[str, Set[str]] = None):
        self.cache = cache or {}

    def get(self, package_name: str) -> Set[str]:
        return self.cache[package_name]

    async def load_api(self, pkg_set):
        # This is debatable
        timeout = ClientTimeout(total=None)
        async with ClientSession(raise_for_status=True, timeout=timeout) as session:
            await asyncio.gather(*[self.set_api(pkg, session)
                                   for pkg in pkg_set if pkg not in self.cache])

    async def set_api(self, pkg, session):
        url = ('https://api.launchpad.net/1.0/ubuntu/+archive/'
               'primary?ws.op=getPublishedSources&'
               'source_name={}&exact_match=true'.format(pkg))
        try:
            all_versions = set()
            while True:
                response = await session.request(method='GET', url=url)
                resp_json = await response.json()
                if resp_json['entries'] == []:
                    self.cache[pkg] = {}
                    break
                for release in resp_json['entries']:
                    all_versions.add(release['source_package_version'])
                if resp_json.get('next_collection_link'):
                    url = resp_json['next_collection_link']
                else:
                    break
            self.cache[pkg] = all_versions
        except ClientResponseError:
            self.cache[pkg] = {}
