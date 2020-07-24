# Copyright (c)  nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an 'AS IS' BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import asyncio
from typing import Mapping
from typing import Set
from typing import List
from urllib.error import HTTPError
from urllib.request import urlopen
import xml.etree.ElementTree as ET

import requests
from aiohttp import ClientSession
from aiohttp.client_exceptions import ClientResponseError

# TODO : 1) Declare a proper blueprint for all VersionAPI classes
#  2) Use async in every VersionAPI class. This will greatly speed up
#  the import process.


class VersionAPI:
    def __init__(self, cache: Mapping[str, Set[str]] = None):
        self.cache = cache or {}

    def get(self, package_name: str) -> Set[str]:
        return self.cache.get(package_name, set())


class LaunchpadVersionAPI(VersionAPI):
    async def load_api(self, pkg_set):
        async with ClientSession(raise_for_status=True) as session:
            await asyncio.gather(
                *[self.set_api(pkg, session) for pkg in pkg_set if pkg not in self.cache]
            )

    async def set_api(self, pkg, session):
        if pkg in self.cache:
            return
        url = (
            "https://api.launchpad.net/1.0/ubuntu/+archive/"
            "primary?ws.op=getPublishedSources&"
            "source_name={}&exact_match=true".format(pkg)
        )
        try:
            all_versions = set()
            while True:
                response = await session.request(method="GET", url=url)
                resp_json = await response.json()
                if resp_json["entries"] == []:
                    self.cache[pkg] = {}
                    break
                for release in resp_json["entries"]:
                    all_versions.add(release["source_package_version"])
                if resp_json.get("next_collection_link"):
                    url = resp_json["next_collection_link"]
                else:
                    break
            self.cache[pkg] = all_versions
        except (ClientResponseError, asyncio.exceptions.TimeoutError):
            self.cache[pkg] = {}


class PypiVersionAPI(VersionAPI):
    def get(self, package_name: str) -> Set[str]:
        package_name = package_name.strip()

        if package_name not in self.cache:
            releases = set()
            try:
                with urlopen(f"https://pypi.org/pypi/{package_name}/json") as response:
                    json_file = json.load(response)
                    releases = set(json_file["releases"])
            except HTTPError as e:
                if e.code == 404:
                    # PyPi does not have data about this package
                    pass
                else:
                    raise

            self.cache[package_name] = releases

        return self.cache[package_name]


class CratesVersionAPI(VersionAPI):
    def get(self, package_name: str) -> Set[str]:
        package_name = package_name.strip()

        if package_name not in self.cache:
            releases = set()

            try:
                with urlopen(f"https://crates.io/api/v1/crates/{package_name}") as response:
                    response = json.load(response)
                    for version_info in response["versions"]:
                        releases.add(version_info["num"])
            except HTTPError as e:
                if e.code == 404:
                    pass
                else:
                    raise

            self.cache[package_name] = releases

        return self.cache[package_name]


class RubyVersionAPI(VersionAPI):

    base_endpt = "https://rubygems.org/api/v1/versions/{}.json"

    def call_api(self, pkg_name) -> List:
        end_pt = self.base_endpt.format(pkg_name)
        try:
            resp = requests.get(end_pt)
            return resp.json()
        # this covers 404 alright
        except JSONDecodeError:
            return []

    def get_all_version_of_package(self, pkg_name) -> Set[str]:
        all_versions = set()
        if self.cache.get(pkg_name):
            return self.cache.get(pkg_name)

        json_resp = self.call_api(pkg_name)
        for release in json_resp:
            all_versions.add(release["number"])
        self.cache[pkg_name] = all_versions
        return all_versions


class NpmVersionAPI(VersionAPI):
    def get(self, package_name: str) -> Set[str]:
        """
        Returns all versions available for a module
        """
        package_name = package_name.strip()

        if package_name not in self.cache:
            releases = set()
            try:
                with urlopen(f"https://registry.npmjs.org/{package_name}") as response:
                    data = json.load(response)
                    releases = {v for v in data.get("versions", {})}
            except HTTPError as e:
                if e.code == 404:
                    # NPM registry has no data regarding this package, we skip these
                    pass
                else:
                    raise

            self.cache[package_name] = releases

        return self.cache[package_name]


class DebianVersionAPI(VersionAPI):
    async def load_api(self, pkg_set):
        # Need to set the headers, because the Debian API upgrades
        # the connection to HTTP 2.0
        async with ClientSession(
            raise_for_status=True, headers={"Connection": "keep-alive"}
        ) as session:
            await asyncio.gather(
                *[self.set_api(pkg, session) for pkg in pkg_set if pkg not in self.cache]
            )

    async def set_api(self, pkg, session, retry_count=5):
        if pkg in self.cache:
            return
        url = "https://sources.debian.org/api/src/{}".format(pkg)
        try:
            all_versions = set()
            response = await session.request(method="GET", url=url)
            resp_json = await response.json()

            if resp_json.get("error") or not resp_json.get("versions"):
                self.cache[pkg] = {}
                return
            for release in resp_json["versions"]:
                all_versions.add(release["version"])

            self.cache[pkg] = all_versions
        # TODO : Handle ServerDisconnectedError by using some sort of
        # retry mechanism
        except (ClientResponseError, asyncio.exceptions.TimeoutError, ServerDisconnectedError):
            self.cache[pkg] = {}


class MavenVersionAPI(VersionAPI):
    def load_to_api(self, pkg_name: str) -> None:
        if pkg_name in self.cache:
            return

        artifact_comps = pkg_name.split(":")
        endpoint = self.artifact_url(artifact_comps)
        resp = requests.get(endpoint).content

        try:
            xml_resp = ET.ElementTree(ET.fromstring(resp.decode("utf-8")))
            self.cache[pkg_name] = self.extract_versions(xml_resp)
        except ET.ParseError:
            self.cache[pkg_name] = set()

    @staticmethod
    def artifact_url(artifact_comps: List[str]) -> str:
        base_url = "https://repo1.maven.org/maven2/{}"
        group_id, artifact_id = artifact_comps
        group_url = group_id.replace(".", "/")
        suffix = group_url + "/" + artifact_id + "/" + "maven-metadata.xml"
        endpoint = base_url.format(suffix)

        return endpoint

    @staticmethod
    def extract_versions(xml_response: ET.ElementTree) -> Set[str]:
        all_versions = set()
        for child in xml_response.getroot().iter():
            if child.tag == "version":
                all_versions.add(child.text)

        return all_versions


class NugetVersionAPI(VersionAPI):
    def load_to_api(self, pkg_name: str) -> None:
        if pkg_name in self.cache:
            return
        endpoint = self.nuget_url(pkg_name)
        try:
            resp = requests.get(endpoint).json()
        # pkg_name=Microsoft.NETCore.UniversalWindowsPlatform triggers
        # JSONDecodeError.
        except json.decoder.JSONDecodeError:
            self.cache[pkg_name] = set()
            return

        self.cache[pkg_name] = self.extract_versions(resp)

    @staticmethod
    def nuget_url(pkg_name: str) -> str:
        base_url = "https://api.nuget.org/v3/registration5-semver1/{}/index.json"
        return base_url.format(pkg_name.lower())

    @staticmethod
    def extract_versions(resp: dict) -> Set[str]:
        all_versions = set()
        try:
            for entry in resp["items"][0]["items"]:
                all_versions.add(entry["catalogEntry"]["version"])
        # json response for YamlDotNet.Signed triggers this exception
        except KeyError:
            pass

        return all_versions


class ComposerVersionAPI(VersionAPI):
    def load_to_api(self, pkg_name: str) -> None:
        if pkg_name in self.cache:
            return

        endpoint = self.composer_url(pkg_name)
        json_resp = requests.get(endpoint).json()
        self.cache[pkg_name] = self.extract_versions(json_resp, pkg_name)

    @staticmethod
    def composer_url(pkg_name: str) -> str:
        vendor, name = pkg_name.split("/")
        return f"https://repo.packagist.org/p/{vendor}/{name}.json"

    @staticmethod
    def extract_versions(resp: dict, pkg_name: str) -> Set[str]:
        all_versions = resp["packages"][pkg_name].keys()
        all_versions = {version.replace("v", "") for version in all_versions if "dev" not in version}  # nopep8
        # This if statement ensures, that all_versions contains only released versions
        # See https://github.com/composer/composer/blob/44a4429978d1b3c6223277b875762b2930e83e8c/doc/articles/versions.md#tags  # nopep8
        # for explanation of removing 'v'
        return all_versions
