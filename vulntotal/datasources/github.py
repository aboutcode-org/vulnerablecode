#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from typing import Iterable

from dotenv import load_dotenv

from vulnerabilities import utils
from vulntotal.validator import DataSource
from vulntotal.validator import VendorData
from vulntotal.vulntotal_utils import get_item
from vulntotal.vulntotal_utils import github_constraints_satisfied

logger = logging.getLogger(__name__)


class GithubDataSource(DataSource):
    spdx_license_expression = "TODO"
    license_url = "TODO"

    def fetch_github(self, graphql_query):
        """
        Requires GitHub API key in .env file
        For example::

                GH_TOKEN="your-github-token"
        """
        load_dotenv()
        return utils.fetch_github_graphql_query(graphql_query)

    def datasource_advisory(self, purl) -> Iterable[VendorData]:
        end_cursor = ""
        interesting_edges = []
        while True:
            queryset = generate_graphql_payload(purl, end_cursor)
            response = self.fetch_github(queryset)
            self._raw_dump.append(response)
            security_advisories = get_item(response, "data", "securityVulnerabilities")
            interesting_edges.extend(extract_interesting_edge(security_advisories["edges"], purl))
            end_cursor = get_item(security_advisories, "pageInfo", "endCursor")
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
            "cargo": "RUST",
            "npm": "NPM",
            "hex": "ERLANG",
        }


def parse_advisory(interesting_edges) -> Iterable[VendorData]:
    for edge in interesting_edges:
        node = edge["node"]
        aliases = [aliase["value"] for aliase in get_item(node, "advisory", "identifiers")]
        affected_versions = node["vulnerableVersionRange"].strip().replace(" ", "").split(",")
        parsed_fixed_versions = get_item(node, "firstPatchedVersion", "identifier")
        fixed_versions = [parsed_fixed_versions] if parsed_fixed_versions else []
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
