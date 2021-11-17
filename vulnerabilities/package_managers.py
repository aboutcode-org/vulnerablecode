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
import os
import asyncio
import dataclasses
import xml.etree.ElementTree as ET
from datetime import datetime
from json import JSONDecodeError
from subprocess import check_output
from typing import Set, List, MutableMapping, Optional
from django.utils.dateparse import parse_datetime

from aiohttp import ClientSession
import aiohttp
from aiohttp.client_exceptions import ClientResponseError
from aiohttp.client_exceptions import ServerDisconnectedError
from bs4 import BeautifulSoup
from dateutil import parser as dateparser


@dataclasses.dataclass(frozen=True)
class Version:
    value: str
    release_date: Optional[datetime] = None


@dataclasses.dataclass
class VersionResponse:
    valid_versions: Set[str] = dataclasses.field(default_factory=set)
    newer_versions: Set[str] = dataclasses.field(default_factory=set)


class GraphQLError(Exception):
    pass


class VersionAPI:
    def __init__(self, cache: MutableMapping[str, Set[Version]] = None):
        self.cache = cache or {}

    def get(self, package_name, until=None) -> VersionResponse:
        new_versions = set()
        valid_versions = set()
        for version in self.cache.get(package_name, set()):
            if until and version.release_date and version.release_date > until:
                new_versions.add(version.value)
                continue
            valid_versions.add(version.value)

        return VersionResponse(
            valid_versions=valid_versions, newer_versions=new_versions
        )

    async def load_api(self, pkg_set):
        async with client_session() as session:
            await asyncio.gather(
                *[self.fetch(pkg, session) for pkg in pkg_set if pkg not in self.cache]
            )

    async def fetch(self, pkg, session):
        """
        Override this method to fetch the pkg's version in the cache
        """
        raise NotImplementedError


def client_session(**kwargs):
    # trust_env is important so that https_proxy environment variable is used
    # in proxy protected environments
    return ClientSession(raise_for_status=True, trust_env=True, **kwargs)


class LaunchpadVersionAPI(VersionAPI):

    package_type = "deb"

    async def fetch(self, pkg, session):
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
                    self.cache[pkg] = set()
                    break
                for release in resp_json["entries"]:
                    all_versions.add(
                        Version(
                            value=release["source_package_version"].replace("0:", ""),
                            release_date=release["date_published"],
                        )
                    )
                if resp_json.get("next_collection_link"):
                    url = resp_json["next_collection_link"]
                else:
                    break
            self.cache[pkg] = all_versions
        except (
            ClientResponseError,
            asyncio.exceptions.TimeoutError,
            ServerDisconnectedError,
        ):
            self.cache[pkg] = set()


class PypiVersionAPI(VersionAPI):

    package_type = "pypi"

    async def fetch(self, pkg, session):
        url = f"https://pypi.org/pypi/{pkg}/json"
        versions = set()
        try:
            response = await session.request(method="GET", url=url)
            response = await response.json()
            for version, download_items in response["releases"].items():
                if download_items:
                    latest_download_item = max(
                        download_items,
                        key=lambda download_item: dateparser.parse(
                            download_item["upload_time_iso_8601"]
                        ),
                    )
                    versions.add(
                        Version(
                            value=version,
                            release_date=dateparser.parse(
                                latest_download_item["upload_time_iso_8601"]
                            ),
                        )
                    )
        except ClientResponseError:
            # PYPI removed this package.
            # https://www.zdnet.com/article/twelve-malicious-python-libraries-found-and-removed-from-pypi/  # nopep8
            pass
        self.cache[pkg] = versions


class CratesVersionAPI(VersionAPI):

    package_type = "cargo"

    async def fetch(self, pkg, session):
        url = f"https://crates.io/api/v1/crates/{pkg}"
        response = await session.request(method="GET", url=url)
        response = await response.json()
        versions = set()
        for version_info in response["versions"]:
            versions.add(
                Version(
                    value=version_info["num"],
                    release_date=dateparser.parse(version_info["updated_at"]),
                )
            )

        self.cache[pkg] = versions


class RubyVersionAPI(VersionAPI):

    package_type = "gem"

    async def fetch(self, pkg, session):
        url = f"https://rubygems.org/api/v1/versions/{pkg}.json"
        versions = set()
        try:
            response = await session.request(method="GET", url=url)
            response = await response.json()
            for release in response:
                versions.add(
                    Version(
                        value=release["number"],
                        release_date=dateparser.parse(release["created_at"]),
                    )
                )
        except (ClientResponseError, JSONDecodeError):
            pass

        self.cache[pkg] = versions


class NpmVersionAPI(VersionAPI):

    package_type = "npm"

    async def fetch(self, pkg, session):
        url = f"https://registry.npmjs.org/{pkg}"
        versions = set()
        try:
            response = await session.request(method="GET", url=url)
            response = await response.json()
            for version in response.get("versions", []):
                release_date = response.get("time", {}).get(version)
                if release_date:
                    release_date = dateparser.parse(release_date)
                    versions.add(Version(value=version, release_date=release_date))
                else:
                    versions.add(Version(value=version, release_date=None))

        except ClientResponseError:
            pass

        self.cache[pkg] = versions


class DebianVersionAPI(VersionAPI):

    package_type = "deb"

    async def load_api(self, pkg_set):
        # Need to set the headers, because the Debian API upgrades
        # the connection to HTTP 2.0
        async with client_session(headers={"Connection": "keep-alive"}) as session:
            await asyncio.gather(
                *[self.fetch(pkg, session) for pkg in pkg_set if pkg not in self.cache]
            )

    async def fetch(self, pkg, session, retry_count=5):
        url = "https://sources.debian.org/api/src/{}".format(pkg)
        try:
            all_versions = set()
            response = await session.request(method="GET", url=url)
            resp_json = await response.json()

            if resp_json.get("error") or not resp_json.get("versions"):
                self.cache[pkg] = set()
                return
            for release in resp_json["versions"]:
                all_versions.add(Version(value=release["version"].replace("0:", "")))

            self.cache[pkg] = all_versions
        # TODO : Handle ServerDisconnectedError by using some sort of
        # retry mechanism
        except (
            ClientResponseError,
            asyncio.exceptions.TimeoutError,
            ServerDisconnectedError,
        ):
            self.cache[pkg] = set()


class MavenVersionAPI(VersionAPI):

    package_type = "maven"

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
    def extract_versions(xml_response: ET.ElementTree) -> Set[Version]:
        all_versions = set()
        for child in xml_response.getroot().iter():
            if child.tag == "version" and child.text:
                all_versions.add(Version(child.text))

        return all_versions


class NugetVersionAPI(VersionAPI):

    package_type = "nuget"

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
    def extract_versions(resp: dict) -> Set[Version]:
        all_versions = set()
        try:
            for entry_group in resp["items"]:
                for entry in entry_group["items"]:
                    all_versions.add(
                        Version(
                            value=entry["catalogEntry"]["version"],
                            release_date=dateparser.parse(
                                entry["catalogEntry"]["published"]
                            ),
                        )
                    )
        # FIXME: json response for YamlDotNet.Signed triggers this exception.
        # Some packages with many versions give a response of a list of endpoints.
        # In such cases rather, we should collect data from those endpoints.
        except KeyError:
            pass

        return all_versions


class ComposerVersionAPI(VersionAPI):

    package_type = "composer"

    async def fetch(self, pkg, session) -> None:
        endpoint = self.composer_url(pkg)
        if endpoint:
            resp = await session.request(method="GET", url=endpoint)
            resp = await resp.json()
            self.cache[pkg] = self.extract_versions(resp, pkg)

    @staticmethod
    def composer_url(pkg_name: str) -> Optional[str]:
        try:
            vendor, name = pkg_name.split("/")
        except ValueError:
            # TODO Log this
            return
        return f"https://repo.packagist.org/p/{vendor}/{name}.json"

    @staticmethod
    def extract_versions(resp: dict, pkg_name: str) -> Set[Version]:
        all_versions = set()
        for version in resp["packages"][pkg_name]:
            if "dev" in version:
                continue

            # This if statement ensures, that all_versions contains only released versions
            # See https://github.com/composer/composer/blob/44a4429978d1b3c6223277b875762b2930e83e8c/doc/articles/versions.md#tags  # nopep8
            # for explanation of removing 'v'
            all_versions.add(
                Version(
                    value=version.lstrip("v"),
                    release_date=dateparser.parse(
                        resp["packages"][pkg_name][version]["time"]
                    ),
                )
            )
        return all_versions


class GitHubTagsAPI(VersionAPI):

    package_type = "github"
    GQL_QUERY = """
    query getTags($name: String!, $owner: String!, $after: String)
    {
        repository(name: $name, owner: $owner) {
            refs(refPrefix: "refs/tags/", first: 100, after: $after) {
                totalCount
                pageInfo {
                    endCursor
                    hasNextPage
                }
                nodes {
                    name
                    target {
                        ... on Commit {
                            committedDate
                        }
                        ... on Tag {
                                target {
                                ... on Commit {
                                    committedDate
                                }
                            }
                        }
                    }
                }
            }
        }
    }"""

    def __init__(self, cache: MutableMapping[str, Set[Version]] = None):
        self.gh_token = os.getenv("GH_TOKEN")
        super().__init__(cache=cache)

    async def fetch(self, owner_repo: str, session: aiohttp.ClientSession) -> None:
        """
        owner_repo is a string of format "{repo_owner}/{repo_name}"
        Example value of owner_repo = "nexB/scancode-toolkit"
        """
        self.cache[owner_repo] = set()
        if self.gh_token:
            # graphql api cannot work without api token
            session.headers["Authorization"] = "token " + self.gh_token
            endpoint = f"https://api.github.com/graphql"
            owner, name = owner_repo.split("/")
            query = {
                "query": self.GQL_QUERY,
                "variables": {"name": name, "owner": owner},
            }

            while True:
                response = await session.post(endpoint, json=query)
                resp_json = await response.json()

                if "errors" in resp_json:
                    raise GraphQLError(resp_json["errors"])

                refs = resp_json["data"]["repository"]["refs"]

                for entry in refs["nodes"]:
                    name = entry["name"]
                    target = entry["target"]
                    # in case the tag is a signed tag, then the commit info is in target['target']
                    if "committedDate" not in target:
                        target = target["target"]
                    if "committedDate" in target:
                        release_date = dateparser.parse(target["committedDate"])
                    else:
                        # but tags can actually point to tree and not commit, so there is no date
                        # probably this only happened for linux. Github cannot even properly display it.
                        # https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/refs/tags/v2.6.11
                        release_date = None
                    self.cache[owner_repo].add(
                        Version(value=name, release_date=release_date)
                    )

                if not refs["pageInfo"]["hasNextPage"]:
                    break
                # to fetch next page, we just set the after variable to endCursor
                query["variables"]["after"] = refs["pageInfo"]["endCursor"]

        else:
            # In case we don't have GH_TOKEN, we use the svn ls method to get the tags
            # It allows to get all the information needed in one request without any rate limiting
            # this method is however not scalable for larger repo and the api is unresponsive
            # for repo with > 50 tags
            endpoint = f"https://github.com/{owner_repo}"
            tags_xml = check_output(
                ["svn", "ls", "--xml", f"{endpoint}/tags"], text=True
            )
            elements = ET.fromstring(tags_xml)
            for entry in elements.iter("entry"):
                name = entry.find("name").text
                release_date = dateparser.parse(entry.find("commit/date").text)


class HexVersionAPI(VersionAPI):
    async def fetch(self, pkg, session):
        url = f"https://hex.pm/api/packages/{pkg}"
        versions = set()
        try:
            response = await session.request(method="GET", url=url)
            response = await response.json()
            for release in response["releases"]:
                versions.add(
                    Version(
                        value=release["version"],
                        release_date=dateparser.parse(release["inserted_at"]),
                    )
                )
        except (ClientResponseError, JSONDecodeError):
            pass

        self.cache[pkg] = versions


class GoproxyVersionAPI(VersionAPI):

    package_type = "golang"
    pkg_mappings = {}

    @staticmethod
    def trim_package_path(pkg: str) -> Optional[str]:
        """github advisories for golang is using package names(e.g. https://github.com/advisories/GHSA-jp4j-47f9-2vc3), yet goproxy works with module names(see https://golang.org/ref/mod#goproxy-protocol).
        this method removes the last part of a package path, and returns the remaining as the module name.
        """
        # some advisories contains this prefix in package name, e.g. https://github.com/advisories/GHSA-7h6j-2268-fhcm
        pkg = pkg.removeprefix("https://pkg.go.dev/")
        parts = pkg.split("/")
        if len(parts) >= 2:
            return "/".join(parts[:-1])
        else:
            return None

    @staticmethod
    def escape_path(path: str) -> str:
        """escpe uppercase in module/version name"""
        escaped_path = ""
        for c in path:
            if c >= "A" and c <= "Z":
                escaped_path += "!" + chr(ord(c) + ord("a") - ord("A"))
            else:
                escaped_path += c
        return escaped_path

    async def fetch(self, pkg: str, session: ClientSession):
        # escpe uppercase in module path
        escaped_pkg = GoproxyVersionAPI.escape_path(pkg)
        trimmed_pkg = pkg
        resp_text = None
        err_pkgs = []
        while escaped_pkg is not None:
            url = f"https://proxy.golang.org/{escaped_pkg}/@v/list"
            try:
                response = await session.request(method="GET", url=url)
                resp_text = await response.text()
            except:
                err_pkgs.append(trimmed_pkg)
                escaped_pkg = GoproxyVersionAPI.trim_package_path(escaped_pkg)
                trimmed_pkg = GoproxyVersionAPI.trim_package_path(trimmed_pkg) or ""
                continue
            break
        if resp_text is None:
            print("error fetch versions from goproxy: ", err_pkgs)
            return
        self.pkg_mappings[pkg] = trimmed_pkg
        versions = set()
        for version_info in resp_text.split("\n"):
            v = version_info.split()
            if len(v) > 0:
                value = v[0]
                if len(v) > 1:
                    release_date = parse_datetime(v[1])
                else:
                    escaped_ver = GoproxyVersionAPI.escape_path(value)
                    try:
                        response = await session.request(
                            method="GET",
                            url=f"https://proxy.golang.org/{escaped_pkg}/@v/{escaped_ver}.info",
                        )
                        resp_json = await response.json()
                        release_date = parse_datetime(resp_json.get("Time", ""))
                    except:
                        release_date = None
                versions.add(Version(value=value, release_date=release_date))
        self.cache[pkg] = versions
