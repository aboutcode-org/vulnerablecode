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
from packageurl import PackageURL

from vulnerabilities import utils
from vulntotal.validator import DataSource
from vulntotal.validator import InvalidCVEError
from vulntotal.validator import VendorData
from vulntotal.vulntotal_utils import get_item
from vulntotal.vulntotal_utils import github_constraints_satisfied

logger = logging.getLogger(__name__)


class GithubDataSource(DataSource):
    spdx_license_expression = "TODO"
    license_url = "TODO"

    def fetch_github(self, graphql_query):
        """
        Requires GitHub API key in .env file.
        For example::

                GH_TOKEN="your-github-token"
        """
        load_dotenv()
        return utils.fetch_github_graphql_query(graphql_query)

    def datasource_advisory(self, purl) -> Iterable[VendorData]:
        end_cursor = ""
        interesting_edges = []
        while True:
            queryset = generate_graphql_payload_from_purl(purl, end_cursor)
            response = self.fetch_github(queryset)
            self._raw_dump.append(response)
            security_advisories = get_item(response, "data", "securityVulnerabilities")
            interesting_edges.extend(extract_interesting_edge(security_advisories["edges"], purl))
            end_cursor = get_item(security_advisories, "pageInfo", "endCursor")
            if not security_advisories["pageInfo"]["hasNextPage"]:
                break
        return parse_advisory(interesting_edges, purl)

    def datasource_advisory_from_cve(self, cve: str) -> Iterable[VendorData]:
        if not cve.upper().startswith("CVE-"):
            raise InvalidCVEError

        queryset = generate_graphql_payload_from_cve(cve)
        response = self.fetch_github(queryset)
        self._raw_dump = [response]
        grouped_advisory = group_advisory_by_package(response, cve)

        for advisory in grouped_advisory:
            ecosystem = get_item(advisory, "package", "ecosystem")
            ecosystem = get_purl_type(ecosystem)
            package_name = get_item(advisory, "package", "name")
            purl = PackageURL.from_string(f"pkg:{ecosystem}/{package_name}")
            yield VendorData(
                purl=purl,
                aliases=sorted(list(set(advisory.get("identifiers", None)))),
                affected_versions=sorted(list(set(advisory.get("firstPatchedVersion", None)))),
                fixed_versions=sorted(list(set(advisory.get("vulnerableVersionRange", None)))),
            )

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
            "pub": "PUB",
        }


def parse_advisory(interesting_edges, purl) -> Iterable[VendorData]:
    """
    Parse the GraphQL response and yield VendorData instances.

    Parameters:
        interesting_edges (list): List of edges containing security advisory.
        purl (PackageURL): PURL to be included in VendorData.

    Yields:
        VendorData instance containing purl, aliases, affected_versions and fixed_versions.
    """
    for edge in interesting_edges:
        node = edge["node"]
        aliases = [aliase["value"] for aliase in get_item(node, "advisory", "identifiers")]
        affected_versions = node["vulnerableVersionRange"].strip().replace(" ", "").split(",")
        parsed_fixed_versions = get_item(node, "firstPatchedVersion", "identifier")
        fixed_versions = [parsed_fixed_versions] if parsed_fixed_versions else []
        yield VendorData(
            purl=PackageURL(purl.type, purl.namespace, purl.name),
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


def generate_graphql_payload_from_purl(purl, end_cursor=""):
    """
    Generate a GraphQL payload for querying security vulnerabilities related to a PURL.

    Parameters:
        purl (PackageURL): The PURL to search for vulnerabilities.
        end_cursor (str): An optional end cursor to use for pagination.

    Returns:
        dict: A dictionary containing the GraphQL query string with ecosystem and package.
    """
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


def generate_graphql_payload_from_cve(cve: str):
    """
    Generate a GraphQL payload for querying security advisories related to a CVE.

    Parameters:
    - cve (str): CVE identifier string to search for.

    Returns:
    - dict: Dictionary containing the GraphQL query string with the CVE identifier substituted in.
    """
    GRAPHQL_QUERY_TEMPLATE = """
    query {
      securityAdvisories(first: 100, identifier: { type: CVE, value: "%s" }) {
        nodes {
          vulnerabilities(first: 100) {
            nodes {
              package {
                ecosystem
                name
              }
              advisory {
                identifiers {
                  type
                  value
                }
              }
              firstPatchedVersion {
                identifier
              }
              vulnerableVersionRange
            }
          }
        }
      }
    }
    """
    return {"query": GRAPHQL_QUERY_TEMPLATE % (cve)}


def get_purl_type(github_ecosystem):
    """
    Return the corresponding purl type for a given GitHub ecosystem string.

    Parameters:
        github_ecosystem (str): The GitHub ecosystem string.

    Returns:
        str or None: The corresponding purl type string, or None if the ecosystem is not supported.
    """
    ecosystems = GithubDataSource.supported_ecosystem()
    for key, val in ecosystems.items():
        if val == github_ecosystem.upper():
            return key.lower()
    return None


def group_advisory_by_package(advisories_dict, cve):
    """
    Extract security advisory information from a dictionary and groups them by package.

    Parameters:
        advisories_dict (dict): Dictionary containing security advisory. The dictionary
            should have the following structure:
            {
              "data":{
                "securityAdvisories":{
                  "nodes":[
                    {
                      "vulnerabilities":{
                        "nodes":[
                          {
                            "package": {
                                "ecosystem": str,
                                "name": str
                            },
                            "advisory":{
                              "identifiers":[
                                { "value": str },
                                ...
                              ]
                            },
                            "firstPatchedVersion":{
                              "identifier": str
                            },
                            "vulnerableVersionRange": str
                          },
                          ...
                        ]
                      }
                    },
                    ...
                  ]
                }
              }
            }

        cve (str): Used for filtering out advisory non maching CVEs.

    Returns:
        list: List of dict containing advisory for package. Each dict
            in the list represents advisory for a package and has the following keys:

            package (dict): Dict containing ecosystem and package name.
            identifiers (list of str): List of identifiers CVE and GHSA.
            firstPatchedVersion (list of str): List of first patched versions.
            vulnerableVersionRange (list of str): List of vulnerable version ranges.
    """
    advisories = advisories_dict["data"]["securityAdvisories"]["nodes"]
    output = []

    for advisory in advisories:
        for vulnerability in advisory["vulnerabilities"]["nodes"]:
            package = vulnerability["package"]
            advisory_ids = [
                identifier["value"] for identifier in vulnerability["advisory"]["identifiers"]
            ]

            # Skip advisory if required CVE is not present in advisory.
            # GraphQL query for `CVE-2022-2922` may also include advisory for `CVE-2022-29221`
            # `CVE-2022-29222` and `CVE-2022-29229`
            if cve not in advisory_ids:
                continue
            first_patched_version = vulnerability["firstPatchedVersion"]["identifier"]
            vulnerable_version_range = vulnerability["vulnerableVersionRange"]

            # Check if a vulnerability for the same package is already in the output list
            existing_vulnerability = next((v for v in output if v["package"] == package), None)
            if existing_vulnerability:
                existing_vulnerability["identifiers"] += advisory_ids
                existing_vulnerability["firstPatchedVersion"].append(first_patched_version)
                existing_vulnerability["vulnerableVersionRange"].append(vulnerable_version_range)
            else:
                output.append(
                    {
                        "package": package,
                        "identifiers": advisory_ids,
                        "firstPatchedVersion": [first_patched_version],
                        "vulnerableVersionRange": [vulnerable_version_range],
                    }
                )
    return output
