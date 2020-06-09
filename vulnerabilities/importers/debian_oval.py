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
import dataclasses
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Set
import xml.etree.ElementTree as ET


from aiohttp import ClientSession
from aiohttp.client_exceptions import ClientResponseError, ServerDisconnectedError
import requests


from vulnerabilities.data_source import OvalDataSource, DataSourceConfiguration


@dataclasses.dataclass
class DebianOvalConfiguration(DataSourceConfiguration):
    releases: list
    etags: dict


class DebianOvalDataSource(OvalDataSource):

    CONFIG_CLASS = DebianOvalConfiguration

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # we could avoid setting translations, and have it
        # set by default in the OvalParser, but we don't yet know
        # whether all OVAL providers use the same format
        self.translations = {'less than': '<'}
        self.pkg_manager_api = VersionAPI()

    def _fetch(self):
        base_url = 'https://www.debian.org/security/oval/'
        file_name = 'oval-definitions-{}.xml'
        releases = self.config.releases
        for release in releases:
            file_url = base_url + file_name.format(release)
            if not self.create_etag(file_url):
                continue
            resp = requests.get(file_url).content
            yield (
                {'type': 'deb', 'namespace': 'debian',
                    'qualifiers': {'distro': release}
                 },
                ET.ElementTree(ET.fromstring(resp.decode('utf-8')))
            )
        return []

    def set_api(self, packages):
        asyncio.run(self.pkg_manager_api.load_api(packages))

    def create_etag(self, url):
        etag = requests.head(url).headers.get('ETag')
        if not etag:
            return True
        elif url in self.config.etags:
            if self.config.etags[url] == etag:
                return False
        self.config.etags[url] = etag
        return True


class VersionAPI:
    def __init__(self, cache: Mapping[str, Set[str]] = None):
        self.cache = cache or {}

    def get(self, package_name: str) -> Set[str]:
        return self.cache[package_name]

    async def load_api(self, pkg_set):
        # Need to set the headers, because the Debian API upgrades
        # the connection to HTTP 2.0
        async with ClientSession(
            raise_for_status=True,
            headers={'Connection': 'keep-alive'}
        ) as session:
            await asyncio.gather(*[self.set_api(pkg, session)
                                   for pkg in pkg_set if pkg not in self.cache])

    async def set_api(self, pkg, session, retry_count=5):
        if pkg in self.cache:
            return
        url = ('https://sources.debian.org/api/src/{}'.format(pkg))
        try:
            all_versions = set()
            response = await session.request(method='GET', url=url)
            resp_json = await response.json()

            if resp_json.get('error') or not resp_json.get('versions'):
                self.cache[pkg] = {}
                return
            for release in resp_json['versions']:
                all_versions.add(release['version'])

            self.cache[pkg] = all_versions
        # TODO : Handle ServerDisconnectedError by using some sort of
        # retry mechanism
        except (ClientResponseError, asyncio.exceptions.TimeoutError, ServerDisconnectedError):
            self.cache[pkg] = {}
