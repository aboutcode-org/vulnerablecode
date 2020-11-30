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
#  VulnerableCode is a free software  from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import asyncio
import os
import dataclasses
import json
from typing import Set
from typing import Tuple
from typing import List
from typing import Mapping
from typing import Optional

import requests
from dephell_specifier import RangeSpecifier
from packageurl import PackageURL

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.data_source import Reference

from vulnerabilities.package_managers import MavenVersionAPI
from vulnerabilities.package_managers import NugetVersionAPI
from vulnerabilities.package_managers import ComposerVersionAPI
from vulnerabilities.package_managers import PypiVersionAPI
from vulnerabilities.package_managers import RubyVersionAPI

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

    def set_api(self, packages):
        asyncio.run(self.version_api.load_api(packages))

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
            "PIP": PypiVersionAPI,
            "RUBYGEMS": RubyVersionAPI
        }
        versioner = versioners.get(ecosystem)
        if versioner:
            self.version_api = versioner()
            self.set_api(self.collect_packages(ecosystem))

    @staticmethod
    def process_name(ecosystem: str, pkg_name: str) -> Optional[Tuple[Optional[str], str]]:
        if ecosystem == "MAVEN":
            artifact_comps = pkg_name.split(":")
            if len(artifact_comps) != 2:
                return
            ns, name = artifact_comps
            return ns, name
        
        if ecosystem == "COMPOSER":
            vendor, name = pkg_name.split("/")
            return vendor, name

        if ecosystem == "NUGET" or ecosystem == "PIP" or ecosystem == "RUBYGEMS":
            return None, pkg_name

    def collect_packages(self, ecosystem):
        packages = set()
        for page in self.advisories[ecosystem]:
            for adv in page["data"]["securityVulnerabilities"]["edges"]:
                packages.add(adv["node"]["package"]["name"])
        return packages

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
                        aff_range = adv["node"]["vulnerableVersionRange"]
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
                    else : 
                        affected_purls = set()
                        unaffected_purls = set()


                    cve_ids = set()
                    vuln_references = []
                    vuln_desc = adv["node"]["advisory"]["summary"]

                    for vuln in adv["node"]["advisory"]["identifiers"]:
                        if vuln["type"] == "CVE":
                            cve_ids.add(vuln["value"])

                        elif vuln["type"] == "GHSA":
                            ghsa = vuln['value']
                            vuln_references.append(Reference(
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
