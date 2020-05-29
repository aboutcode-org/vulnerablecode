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


from aiohttp import ClientSession
from aiohttp.client_exceptions import ClientResponseError
import requests
from packageurl import PackageURL


from vulnerabilities.data_source import DataSource, DataSourceConfiguration, Advisory
from vulnerabilities.importers import oval_parser



@dataclasses.dataclass
class UbuntuConfiguration(DataSourceConfiguration):
    releases: list

class UbuntuDataSource(DataSource):

    CONFIG_CLASS = UbuntuConfiguration
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        #we could avoid setting translations, and have it
        #set by default in the OvalParser, but we don't yet know
        #whether all OVAL providers use the same format
        self.translations = {'less than':'<'}
        self._versions = VersionAPI()

    def _fetch(self) :
        base_url = 'https://people.canonical.com/~ubuntu-security/oval/'
        file_name = 'com.ubuntu.{}.cve.oval.xml.bz2'
        releases =  self.config.releases
        for release in releases:
            resp = requests.get(base_url + file_name.format(release))
            extracted = bz2.decompress(resp.content)
            yield ET.ElementTree(ET.fromstring(extracted.decode('utf-8')))

    def added_advisories(self) -> List[Advisory] : 
        advisories = []
        for oval_file in self._fetch():
            advisories.extend(self.get_data_from_xml_doc(oval_file))
        return advisories       

    @staticmethod    
    def _collect_pkgs(parsed_oval_data) -> Set : 
        all_pkgs = set()
        for definition_data in  parsed_oval_data:
            for test_data in definition_data['test_data']:
                for package in test_data['package_list']:
                    all_pkgs.add(package)

        return all_pkgs


    def get_data_from_xml_doc(self, xml_doc) -> List[Advisory] :
        all_adv = []
        oval_doc = oval_parser.OvalParser(self.translations, xml_doc)
        raw_data = oval_doc.get_data()
        all_pkgs = self._collect_pkgs(raw_data)

        asyncio.run(self._versions.load_api(all_pkgs))

        for definition_data in raw_data: #definition_data -> Advisory
            vuln_id = definition_data['vuln_id']
            description = definition_data['description']
            affected_purls = set()
            safe_purls = set()
            urls = definition_data['reference_urls']
            for test_data in definition_data['test_data'] : 
                for package in test_data['package_list']:
                    pkg_name = package
                    aff_ver_range = test_data['version_ranges']
                    all_versions = self._versions.get(package)
                    #This filter is to filter out long versions.
                    #50 is limit because that's what db permits atm
                    all_versions = set(filter(lambda x : len(x)<50,all_versions))
                    if not all_versions:
                        continue
                    affected_versions = set(filter(lambda x: x in aff_ver_range,all_versions))
                    safe_versions = all_versions - affected_versions

                    for version in affected_versions:
                        #should we add a qualifier like 'distro:ubuntu'?
                        pkg_url = PackageURL(name=pkg_name,type='deb',version=version)
                        affected_purls.add(pkg_url)

                    for version in safe_versions:
                        #should we add a qualifier like 'distro:ubuntu'?
                        pkg_url = PackageURL(name=pkg_name,type='deb',version=version)
                        safe_purls.add(pkg_url)

            all_adv.append(Advisory(summary=description,impacted_package_urls=affected_purls,
                            resolved_package_urls=safe_purls,cve_id=vuln_id,reference_urls=urls))
        return all_adv



class VersionAPI:
    def __init__(self, cache: Mapping[str, Set[str]] = None):
        self.cache = cache or {}

    def get(self, package_name: str) -> Set[str]:
        return self.cache[package_name]

    async def load_api(self, pkg_set):
        async with ClientSession() as session:
            await asyncio.gather(*[self.set_api(pkg, session) for pkg in pkg_set if pkg not in self.cache])

    async def set_api(self, pkg, session): 
        url = ('https://api.launchpad.net/1.0/ubuntu/+archive/'
            'primary?ws.op=getPublishedSources&'
            'source_name={}&exact_match=true'.format(pkg))
        try:
            all_versions = set()
            while(True):
                response = await session.request(method='GET', url=url)
                response.raise_for_status()
                resp_json = await response.json()
                if resp_json['entries'] == [] : 
                    self.cache[pkg] = {}
                    break
                for release in resp_json['entries']:
                    all_versions.add(release['source_package_version'])
                if resp_json.get('next_collection_link') :
                    url =  resp_json['next_collection_link']
                else:
                    break
            self.cache[pkg] = all_versions
        except ClientResponseError:
            self.cache[pkg] = {}