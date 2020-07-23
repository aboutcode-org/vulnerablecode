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
import dataclasses
import json
from typing import Set
from typing import Tuple
from typing import List
from typing import Mapping
from typing import Optional
import xml.etree.ElementTree as ET

import requests
from dephell_specifier import RangeSpecifier
from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.data_source import VulnerabilityReferenceUnit


# set of all possible values of first '%s' = {'MAVEN','COMPOSER', 'NUGET'}
# second '%s' is interesting, it will have the value '' for the first request,
# since we don't have any value for endCursor at the beginning
# for all the subsequent requests it will have value 'after: "{endCursor}""
query = """
        query{
        securityVulnerabilities(first: 100, ecosystem: %s, %s) {
            edges {
            node {
                advisory {
                identifiers {
                    type
                    value
                }
                summary
                }
                package {
                name
                }
                vulnerableVersionRange
            }
            }
            pageInfo {
            hasNextPage
            endCursor
            }
        }
        }
        """


class GitHubTokenError(Exception):
    pass


@dataclasses.dataclass
class GitHubAPIDataSourceConfiguration(DataSourceConfiguration):
    endpoint: str
    ecosystems: list


class GitHubAPIDataSource(DataSource):

    CONFIG_CLASS = GitHubAPIDataSourceConfiguration

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            self.gh_token = os.environ["GH_TOKEN"]
        except KeyError:
            raise GitHubTokenError("Environment variable GH_TOKEN is missing")

    def __enter__(self):
        self.advisories = self.fetch()

    def updated_advisories(self) -> Set[Advisory]:
        return self.batch_advisories(self.process_response())

    def fetch(self) -> Mapping[str, List[Mapping]]:
        headers = {"Authorization": "token " + self.gh_token}
        api_data = {}
        for ecosystem in self.config.ecosystems:

            api_data[ecosystem] = []
            end_cursor_exp = ""

            while True:

                query_json = {"query": query % (ecosystem, end_cursor_exp)}
                resp = requests.post(self.config.endpoint, headers=headers, json=query_json).json()
                if resp.get("message") == "Bad credentials":
                    raise GitHubTokenError("Invalid GitHub token")

                end_cursor = resp["data"]["securityVulnerabilities"]["pageInfo"]["endCursor"]
                end_cursor_exp = "after: {}".format('"{}"'.format(end_cursor))
                api_data[ecosystem].append(resp)

                if not resp["data"]["securityVulnerabilities"]["pageInfo"]["hasNextPage"]:
                    break
        return api_data

    def set_version_api(self, ecosystem: str) -> None:
        versioners = {
            "MAVEN": MavenVersionAPI,
            "NUGET": NugetVersionAPI,
            "COMPOSER": ComposerVersionAPI,
        }
        versioner = versioners.get(ecosystem)
        if versioner:
            self.version_api = versioner()

    @staticmethod
    def process_name(ecosystem: str, pkg_name: str) -> Optional[Tuple[Optional[str], str]]:
        if ecosystem == "MAVEN":
            artifact_comps = pkg_name.split(":")
            if len(artifact_comps) != 2:
                return
            ns, name = artifact_comps
            return ns, name

        if ecosystem == "NUGET":
            return None, pkg_name

        if ecosystem == "COMPOSER":
            vendor, name = pkg_name.split("/")
            return vendor, name

    def process_response(self) -> List[Advisory]:
        adv_list = []
        for ecosystem in self.advisories:
            self.set_version_api(ecosystem)
            pkg_type = ecosystem.lower()
            for resp_page in self.advisories[ecosystem]:
                for adv in resp_page["data"]["securityVulnerabilities"]["edges"]:
                    name = adv["node"]["package"]["name"]

                    if self.process_name(ecosystem, name):
                        ns, pkg_name = self.process_name(ecosystem, name)
                    else:
                        continue
                    aff_range = adv["node"]["vulnerableVersionRange"]
                    self.version_api.load_to_api(name)
                    aff_vers, unaff_vers = self.categorize_versions(
                        aff_range, self.version_api.get(name)
                    )

                    affected_purls = {
                        PackageURL(name=pkg_name, namespace=ns,
                                   version=version, type=pkg_type)
                        for version in aff_vers
                    }

                    unaffected_purls = {
                        PackageURL(name=pkg_name, namespace=ns,
                                   version=version, type=pkg_type)
                        for version in unaff_vers
                    }

                    cve_ids = set()
                    vuln_references = []
                    vuln_desc = adv["node"]["advisory"]["summary"]

                    for vuln in adv["node"]["advisory"]["identifiers"]:
                        if vuln["type"] == "CVE":
                            cve_ids.add(vuln["value"])

                        elif vuln["type"] == "GHSA":
                            ghsa = vuln['value']
                            vuln_references.append(VulnerabilityReferenceUnit(
                                reference_id=ghsa,
                                url="https://github.com/advisories/{}".format(
                                    ghsa)
                            ))

                    for cve_id in cve_ids:
                        adv_list.append(
                            Advisory(
                                cve_id=cve_id,
                                summary=vuln_desc,
                                impacted_package_urls=affected_purls,
                                resolved_package_urls=unaffected_purls,
                                vuln_references=vuln_references,
                            )
                        )
        return adv_list

    @staticmethod
    def categorize_versions(version_range: str, all_versions: Set[str]) -> Tuple[Set[str], Set[str]]:  # nopep8
        version_range = RangeSpecifier(version_range)
        affected_versions = {
            version for version in all_versions if version in version_range}
        return (affected_versions, all_versions - affected_versions)


class MavenVersionAPI:
    def __init__(self):
        self.cache = {}

    def get(self, pkg_name: str) -> Set[str]:
        return self.cache.get(pkg_name, set())

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
        base_url = "https://repo.maven.apache.org/maven2/{}"
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


class NugetVersionAPI:
    def __init__(self):
        self.cache = {}

    def get(self, pkg_name: str) -> Set[str]:
        return self.cache.get(pkg_name.lower(), set())

    def load_to_api(self, pkg_name: str) -> None:
        if pkg_name in self.cache:
            return
        endpoint = self.nuget_url(pkg_name)
        try:
            resp = requests.get(endpoint).json()
        # pkg_name=Microsoft.NETCore.UniversalWindowsPlatform triggers
        # JSONDecodeError.
        except json.decoder.JSONDecodeError:
            self.cache[pkg_name.lower()] = set()
            return

        self.cache[pkg_name.lower()] = self.extract_versions(resp)

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


class ComposerVersionAPI:
    def __init__(self):
        self.cache = {}

    def get(self, pkg_name: str) -> Set[str]:
        return self.cache.get(pkg_name.lower(), set())

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
        # This filter ensures, that all_versions contains only released versions
        all_versions = set(filter(lambda x: "dev" not in x, all_versions))
        # See https://github.com/composer/composer/blob/44a4429978d1b3c6223277b875762b2930e83e8c/doc/articles/versions.md#tags  # nopep8
        # for explanation of removing 'v'
        all_versions = set(map(lambda x: x.replace("v", ""), all_versions))

        return all_versions
