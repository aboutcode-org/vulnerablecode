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
from dateutil import parser as dateparser
from typing import Set
from typing import Tuple
from typing import List
from typing import Mapping
from typing import Optional

import requests
from packageurl import PackageURL
from univers.version_specifier import VersionSpecifier
from univers.versions import version_class_by_package_type

from vulnerabilities.importer import Advisory
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.package_managers import MavenVersionAPI
from vulnerabilities.package_managers import NugetVersionAPI
from vulnerabilities.package_managers import ComposerVersionAPI
from vulnerabilities.package_managers import PypiVersionAPI
from vulnerabilities.package_managers import GoproxyVersionAPI
from vulnerabilities.package_managers import RubyVersionAPI
from vulnerabilities.severity_systems import scoring_systems
from vulnerabilities.helpers import nearest_patched_package

# set of all possible values of first '%s' = {'MAVEN','COMPOSER', 'NUGET', 'RUBYGEMS', 'PYPI'}
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
                references {
                    url
                }
                severity
                publishedAt
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

# See https://github.com/nexB/vulnerablecode/issues/486
IGNORE_VERSIONS = {
    "0.1-bulbasaur",
    "0.1-charmander",
    "0.3m1",
    "0.3m2",
    "0.3m3",
    "0.3m4",
    "0.3m5",
    "0.4m1",
    "0.4m2",
    "0.4m3",
    "0.4m4",
    "0.4m5",
    "0.5m1",
    "0.5m2",
    "0.5m3",
    "0.5m4",
    "0.5m5",
    "0.6m1",
    "0.6m2",
    "0.6m3",
    "0.6m4",
    "0.6m5",
    "0.6m6",
    "0.7.10p1",
    "0.7.11p1",
    "0.7.11p2",
    "0.7.11p3",
    "0.8.1p1",
    "0.8.3p1",
    "0.8.4p1",
    "0.8.4p2",
    "0.8.6p1",
    "0.8.7p1",
    "0.9-doduo",
    "0.9-eevee",
    "0.9-fearow",
    "0.9-gyarados",
    "0.9-horsea",
    "0.9-ivysaur",
    "2013-01-21T20:33:09+0100",
    "2013-01-23T17:11:52+0100",
    "2013-02-01T20:50:46+0100",
    "2013-02-02T19:59:03+0100",
    "2013-02-02T20:23:17+0100",
    "2013-02-08T17:40:57+0000",
    "2013-03-27T16:32:26+0100",
    "2013-05-09T12:47:53+0200",
    "2013-05-10T17:55:56+0200",
    "2013-05-14T20:16:05+0200",
    "2013-06-01T10:32:51+0200",
    "2013-07-19T09:11:08+0000",
    "2013-08-12T21:48:56+0200",
    "2013-09-11T19-27-10",
    "2013-12-23T17-51-15",
    "2014-01-12T15-52-10",
    "2.0.1rc2-git",
    "3.0.0b3-",
    "3.0b6dev-r41684",
    "-class.-jw.util.version.Version-",
}


class GitHubTokenError(Exception):
    pass


class GitHubAPIImporter(Importer):
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
            "RUBYGEMS": RubyVersionAPI,
            "GO": GoproxyVersionAPI,
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
            try:
                vendor, name = pkg_name.split("/")
            except ValueError:
                # TODO log this
                return None
            return vendor, name

        if ecosystem in ("NUGET", "PIP", "RUBYGEMS", "GO"):
            return None, pkg_name

    @staticmethod
    def extract_references(reference_data):
        references = []
        for ref in reference_data:
            url = ref["url"]
            if "GHSA-" in url.upper():
                reference = Reference(url=url, reference_id=url.split("/")[-1])
            else:
                reference = Reference(url=url)
            references.append(reference)

        return references

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
            pkg_type = self.version_api.package_type
            for resp_page in self.advisories[ecosystem]:
                for adv in resp_page["data"]["securityVulnerabilities"]["edges"]:
                    name = adv["node"]["package"]["name"]
                    cutoff_time = dateparser.parse(adv["node"]["advisory"]["publishedAt"])
                    affected_purls = []
                    unaffected_purls = []
                    if self.process_name(ecosystem, name):
                        ns, pkg_name = self.process_name(ecosystem, name)
                        if hasattr(self.version_api, "module_name_by_package_name"):
                            pkg_name = self.version_api.module_name_by_package_name.get(
                                name, pkg_name
                            )
                        aff_range = adv["node"]["vulnerableVersionRange"]
                        aff_vers, unaff_vers = self.categorize_versions(
                            self.version_api.package_type,
                            aff_range,
                            self.version_api.get(name, until=cutoff_time).valid_versions,
                        )
                        affected_purls = [
                            PackageURL(name=pkg_name, namespace=ns, version=version, type=pkg_type)
                            for version in aff_vers
                        ]

                        unaffected_purls = [
                            PackageURL(name=pkg_name, namespace=ns, version=version, type=pkg_type)
                            for version in unaff_vers
                        ]
                    cve_ids = set()
                    references = self.extract_references(adv["node"]["advisory"]["references"])
                    vuln_desc = adv["node"]["advisory"]["summary"]

                    for identifier in adv["node"]["advisory"]["identifiers"]:
                        # collect CVEs
                        if identifier["type"] == "CVE":
                            cve_ids.add(identifier["value"])

                        # attach the GHSA with severity score
                        if identifier["type"] == "GHSA":
                            for ref in references:
                                if ref.reference_id == identifier["value"]:
                                    ref.severities = [
                                        VulnerabilitySeverity(
                                            system=scoring_systems["cvssv3.1_qr"],
                                            value=adv["node"]["advisory"]["severity"],
                                        )
                                    ]
                                    # Each Node has only one GHSA, hence exit after attaching
                                    # score to this GHSA
                                    break

                    for cve_id in cve_ids:
                        adv_list.append(
                            Advisory(
                                vulnerability_id=cve_id,
                                summary=vuln_desc,
                                affected_packages=nearest_patched_package(
                                    affected_purls, unaffected_purls
                                ),
                                references=references,
                            )
                        )
        return adv_list

    @staticmethod
    def categorize_versions(
        package_type: str, version_range: str, all_versions: Set[str]
    ) -> Tuple[List[str], List[str]]:
        version_class = version_class_by_package_type[package_type]
        version_scheme = version_class.scheme
        version_range = VersionSpecifier.from_scheme_version_spec_string(
            version_scheme, version_range
        )
        affected_versions = []
        unaffected_versions = []
        for version in all_versions:
            if version in IGNORE_VERSIONS:
                continue

            if version_class(version) in version_range:
                affected_versions.append(version)
            else:
                unaffected_versions.append(version)
        return (affected_versions, unaffected_versions)
