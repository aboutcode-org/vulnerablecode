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


import os
import dataclasses
import json
from typing import Set
from typing import Tuple
from typing import List
import xml.etree.ElementTree as ET

import requests
from dephell_specifier import RangeSpecifier
from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration


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
        except KeyError as e:
            raise GitHubTokenMissingError("Envirnomental variable GH_TOKEN is missing")

    def __enter__(self):
        self.advisories = self.fetch()

    def updated_advisories(self) -> Set[Advisory]:
        return self.batch_advisories(self.process_response())

    def fetch(self):
        # set of all possible values of first '%s' = {'MAVEN','COMPOSER', 'NUGET'}
        # second '%s' is interesting, it will have the value '' for the first request,
        # since we don't have any value for endCursor at the beginning
        # for all the subsequent requests it will have value 'after: "{endCursor}"'
        query = """
        query MyQuery {
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
        headers = {"Authorization": "token " + self.gh_token}
        api_data = {}
        for ecosystem in self.config.ecosystems:

            api_data[ecosystem] = []
            end_cursor_exp = ""

            while True:

                query_json = {"query": query % (ecosystem, end_cursor_exp)}
                resp = requests.post(
                    self.config.endpoint, headers=headers, json=query_json
                ).json()

                if resp.get("message") == "Bad credentials":
                    raise GitHubTokenError("Invalid GitHub token")

                end_cursor = resp["data"]["securityVulnerabilities"]["pageInfo"][
                    "endCursor"
                ]
                end_cursor_exp = "after: {}".format('"{}"'.format(end_cursor))
                api_data[ecosystem].append(resp)

                if not resp["data"]["securityVulnerabilities"]["pageInfo"][
                    "hasNextPage"
                ]:
                    break

        return api_data

    def set_version_api(self, ecosystem):

        if ecosystem == "MAVEN":
            self.version_api = MavenVersionAPI()

        elif ecosystem == "NUGET":
            self.version_api = NugetVersionAPI()

        elif ecosystem == "COMPOSER":
            self.version_api = ComposerVersionAPI()

    def process_response(self) -> List[Advisory]:
        adv_list = []
        for ecosystem in self.advisories:
            self.set_version_api(ecosystem)
            pkg_type = ecosystem.lower()
            for resp_page in self.advisories[ecosystem]:
                for adv in resp_page["data"]["securityVulnerabilities"]["edges"]:
                    artifact = adv["node"]["package"]["name"]
                    artifact_comps = artifact.split(":")

                    if len(artifact_comps) != 2:
                        continue

                    ns, pkg_name = artifact_comps
                    aff_range = adv["node"]["vulnerableVersionRange"]
                    # print(pkg_name,aff_range)
                    self.version_api.load_to_api(artifact)
                    aff_vers, unaff_vers = self.categorize_versions(
                        aff_range, self.version_api.get(artifact)
                    )

                    affected_purls = {
                        PackageURL(
                            name=pkg_name, namespace=ns, version=version, type=pkg_type
                        )
                        for version in aff_vers
                    }

                    unaffected_purls = {
                        PackageURL(
                            name=pkg_name, namespace=ns, version=version, type=pkg_type
                        )
                        for version in unaff_vers
                    }

                    cve_ids = set()
                    ref_ids = set()
                    vuln_desc = adv["node"]["advisory"]["summary"]

                    for vuln in adv["node"]["advisory"]["identifiers"]:
                        if vuln["type"] == "CVE":
                            cve_ids.add(vuln["value"])
                        else:
                            ref_ids.add(vuln["value"])
                    for cve_id in cve_ids:
                        adv_list.append(
                            Advisory(
                                cve_id=cve_id,
                                summary=vuln_desc,
                                impacted_package_urls=affected_purls,
                                resolved_package_urls=unaffected_purls,
                                reference_ids=ref_ids,
                            )
                        )
                        print(adv_list[-1])
        return adv_list

    @staticmethod
    def categorize_versions(
        version_range: str, all_versions: Set[str]
    ) -> Tuple[Set[str], Set[str]]:
        version_range = RangeSpecifier(version_range)
        affected_versions = {
            version for version in all_versions if version in version_range
        }
        return (affected_versions, all_versions - affected_versions)


class MavenVersionAPI:
    def __init__(self):
        self.cache = {}

    def get(self, pkg_name: str) -> Set[str]:
        return self.cache.get(pkg_name, set())

    def load_to_api(self, pkg_name: str):

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
        raise NotImplementedError


class ComposerVersionAPI:
    def __init__(self):
        raise NotImplementedError
