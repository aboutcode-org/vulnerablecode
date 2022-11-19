#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnTotal software is licensed under the Apache License version 2.0.
# Data generated with VulnTotal require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnTotal or any VulnTotal
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnTotal and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnTotal should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnTotal is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.


import logging
from typing import Iterable

from packageurl import PackageURL

from vulnerabilities import utils
from vulntotal.validator import DataSource
from vulntotal.validator import VendorData
from vulntotal.vulntotal_utils import github_constraints_satisfied

logger = logging.getLogger(__name__)


class GithubDataSource(DataSource):
    spdx_license_expression = "TODO"
    license_url = "TODO"

    def fetch_github(self, graphql_query):
        return utils.fetch_github_graphql_query(graphql_query)

    def datasource_advisory(self, purl) -> Iterable[VendorData]:
        end_cursor = ""
        interesting_edges = []
        while True:
            queryset = generate_graphql_payload(purl, end_cursor)
            response = self.fetch_github(queryset)
            self._raw_dump.append(response)
            security_advisories = response["data"]["securityVulnerabilities"]
            interesting_edges.extend(extract_interesting_edge(security_advisories["edges"], purl))
            end_cursor = security_advisories["pageInfo"]["endCursor"]
            if not security_advisories["pageInfo"]["hasNextPage"]:
                break
        return parse_advisory(interesting_edges)

    @classmethod
    def supported_ecosystem(cls):
        return {
            "maven": "MAVEN",
            "nuget": "NUGET",
            "composer": "COMPOSER",
            "pypi": "PIP",
            "gem": "RUBYGEMS",
            "golang": "GO",
            "rust": "RUST",
            "npm": "NPM",
            "erlang": "ERLANG",
        }


def parse_advisory(interesting_edges) -> Iterable[VendorData]:
    for edge in interesting_edges:
        aliases = [aliase["value"] for aliase in edge["node"]["advisory"]["identifiers"]]
        affected_versions = (
            edge["node"]["vulnerableVersionRange"].strip().replace(" ", "").split(",")
        )
        fixed_versions = [edge["node"]["firstPatchedVersion"]["identifier"]]
        yield VendorData(
            aliases=sorted(list(set(aliases))),
            affected_versions=sorted(list(set(affected_versions))),
            fixed_versions=sorted(list(set(fixed_versions))),
        )


def extract_interesting_edge(edges, purl):
    interesting_edges = []
    for edge in edges:
        if github_constraints_satisfied(edge["node"]["vulnerableVersionRange"], purl.version):
            interesting_edges.append(edge)
    return interesting_edges


def generate_graphql_payload(purl, end_cursor):
    GRAPHQL_QUERY_TEMPLATE = """
    query{
        securityVulnerabilities(first: 100, ecosystem: %s, package: "%s", %s){
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
                firstPatchedVersion{
                    identifier
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

    supported_ecosystem = GithubDataSource.supported_ecosystem()

    if purl.type not in supported_ecosystem:
        return

    end_cursor_exp = ""
    ecosystem = supported_ecosystem[purl.type]
    package_name = purl.name

    if end_cursor:
        end_cursor_exp = f'after: "{end_cursor}"'

    if purl.type == "maven":
        if not purl.namespace:
            logger.error(f"Invalid Maven PURL {str(purl)}")
            return
        package_name = f"{purl.namespace}:{purl.name}"

    elif purl.type == "composer":
        if not purl.namespace:
            logger.error(f"Invalid Composer PURL {str(purl)}")
            return
        package_name = f"{purl.namespace}/{purl.name}"

    elif purl.type == "golang" and purl.namespace:
        package_name = f"{purl.namespace}/{purl.name}"

    return {"query": GRAPHQL_QUERY_TEMPLATE % (ecosystem, package_name, end_cursor_exp)}
