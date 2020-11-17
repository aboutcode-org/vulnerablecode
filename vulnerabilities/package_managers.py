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
from json import JSONDecodeError
from typing import Mapping
from typing import Set
from typing import List
import xml.etree.ElementTree as ET

from aiohttp import ClientSession
from aiohttp.client_exceptions import ClientResponseError


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
    async def load_api(self, pkg_set):
        async with ClientSession(raise_for_status=True) as session:
            await asyncio.gather(
                *[self.fetch(pkg, session) for pkg in pkg_set if pkg not in self.cache]
            )

    async def fetch(self, pkg, session):
        url = f"https://pypi.org/pypi/{pkg}/json"
        versions = set()
        try:
            response = await session.request(method="GET", url=url)
            response = await response.json()
            versions = set(response["releases"])
        except ClientResponseError:
            # PYPI removed this package.
            # https://www.zdnet.com/article/twelve-malicious-python-libraries-found-and-removed-from-pypi/  # nopep8
            pass
        self.cache[pkg] = versions


class CratesVersionAPI(VersionAPI):
    async def load_api(self, pkg_set):
        async with ClientSession(raise_for_status=True) as session:
            await asyncio.gather(
                *[self.fetch(pkg, session) for pkg in pkg_set if pkg not in self.cache]
            )

    async def fetch(self, pkg, session):
        url = f"https://crates.io/api/v1/crates/{pkg}"
        response = await session.request(method="GET", url=url)
        response = await response.json()
        versions = set()
        for version_info in response["versions"]:
            versions.add(version_info["num"])

        self.cache[pkg] = versions


class RubyVersionAPI(VersionAPI):
    async def load_api(self, pkg_set):
        async with ClientSession(raise_for_status=True) as session:
            await asyncio.gather(
                *[self.fetch(pkg, session) for pkg in pkg_set if pkg not in self.cache]
            )

    async def fetch(self, pkg, session):
        url = f"https://rubygems.org/api/v1/versions/{pkg}.json"
        versions = set()
        try:
            response = await session.request(method="GET", url=url)
            response = await response.json()
            for release in response:
                versions.add(release["number"])
        except (ClientResponseError, JSONDecodeError):
            pass

        self.cache[pkg] = versions


class NpmVersionAPI(VersionAPI):
    async def load_api(self, pkg_set):
        async with ClientSession(raise_for_status=True) as session:
            await asyncio.gather(
                *[self.fetch(pkg, session) for pkg in pkg_set if pkg not in self.cache]
            )

    async def fetch(self, pkg, session):
        url = f"https://registry.npmjs.org/{pkg}"
        versions = set()
        try:
            response = await session.request(method="GET", url=url)
            response = await response.json()
            versions = {v for v in response.get("versions", [])}

        except ClientResponseError:
            pass

        self.cache[pkg] = versions


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
    async def load_api(self, pkg_set):
        async with ClientSession(raise_for_status=True) as session:
            await asyncio.gather(
                *[self.fetch(pkg, session) for pkg in pkg_set if pkg not in self.cache]
            )

    async def fetch(self, pkg, session) -> None:
        artifact_comps = pkg.split(":")
        endpoint = self.artifact_url(artifact_comps)
        try:
            resp = await session.request(method="GET", url=endpoint)
            resp = await resp.read()

        except ClientResponseError:
            self.cache[pkg] = set()
            return

        xml_resp = ET.ElementTree(ET.fromstring(resp.decode("utf-8")))
        self.cache[pkg] = self.extract_versions(xml_resp)

    @staticmethod
    def artifact_url(artifact_comps: List[str]) -> str:
        base_url = "https://repo1.maven.org/maven2/{}"
        try:
            group_id, artifact_id = artifact_comps
        except ValueError:
            if len(artifact_comps) == 1:
                group_id = artifact_comps[0]
                artifact_id = artifact_comps[0].split(".")[-1]

            elif len(artifact_comps) == 3:
                group_id, artifact_id = list(dict.fromkeys(artifact_comps))

            else:
                raise

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
    async def load_api(self, pkg_set):
        async with ClientSession(raise_for_status=True) as session:
            await asyncio.gather(
                *[self.fetch(pkg, session) for pkg in pkg_set if pkg not in self.cache]
            )

    async def fetch(self, pkg, session) -> None:
        endpoint = self.nuget_url(pkg)
        resp = await session.request(method="GET", url=endpoint)
        resp = await resp.json()
        self.cache[pkg] = self.extract_versions(resp)

    @staticmethod
    def nuget_url(pkg_name: str) -> str:
        pkg_name = pkg_name.lower().strip()
        base_url = "https://api.nuget.org/v3/registration5-semver1/{}/index.json"
        return base_url.format(pkg_name)

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
    async def load_api(self, pkg_set):
        async with ClientSession(raise_for_status=True) as session:
            await asyncio.gather(
                *[self.fetch(pkg, session) for pkg in pkg_set if pkg not in self.cache]
            )

    async def fetch(self, pkg, session) -> None:
        endpoint = self.composer_url(pkg)
        resp = await session.request(method="GET", url=endpoint)
        resp = await resp.json()
        self.cache[pkg] = self.extract_versions(resp, pkg)

    @staticmethod
    def composer_url(pkg_name: str) -> str:
        vendor, name = pkg_name.split("/")
        return f"https://repo.packagist.org/p/{vendor}/{name}.json"

    @staticmethod
    def extract_versions(resp: dict, pkg_name: str) -> Set[str]:
        all_versions = resp["packages"][pkg_name].keys()
        all_versions = {
            version.replace("v", "") for version in all_versions if "dev" not in version
        }
        # This if statement ensures, that all_versions contains only released versions
        # See https://github.com/composer/composer/blob/44a4429978d1b3c6223277b875762b2930e83e8c/doc/articles/versions.md#tags  # nopep8
        # for explanation of removing 'v'
        return all_versions


class GitHubTagsAPI(VersionAPI):
    async def load_api(self, repo_set):
        async with ClientSession(raise_for_status=True) as session:
            await asyncio.gather(
                *[
                    self.fetch(owner_repo.lower(), session)
                    for owner_repo in repo_set
                    if owner_repo.lower() not in self.cache
                ]
            )

    async def fetch(self, owner_repo: str, session) -> None:
        # owner_repo is a string of format "{repo_owner}/{repo_name}"
        # Example value of owner_repo = "nexB/scancode-toolkit"
        endpoint = f"https://api.github.com/repos/{owner_repo}/git/refs/tags"
        resp = await session.request(method="GET", url=endpoint)
        resp = await resp.json()
        print(resp)
        self.cache[owner_repo] = [release["ref"].split("/")[-1] for release in resp]
