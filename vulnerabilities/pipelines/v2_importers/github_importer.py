#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from traceback import format_exc as traceback_format_exc
from typing import Callable
from typing import Iterable
from typing import List
from typing import Optional

from cwe2.database import Database
from dateutil import parser as dateparser
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import build_range_from_github_advisory_constraint

from vulnerabilities import severity_systems
from vulnerabilities import utils
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.utils import dedupe
from vulnerabilities.utils import get_cwe_id
from vulnerabilities.utils import get_item


class GitHubAPIImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Collect GitHub advisories."""

    pipeline_id = "github_importer_v2"
    label = "GitHub"
    spdx_license_expression = "CC-BY-4.0"
    license_url = "https://github.com/github/advisory-database/blob/main/LICENSE.md"
    importer_name = "GHSA Importer"

    unfurl_version_ranges = True
    ignorable_versions = frozenset(
        [
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
            "vulnerabilities",
        ]
    )

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

    package_type_by_github_ecosystem = {
        # "MAVEN": "maven",
        # "NUGET": "nuget",
        # "COMPOSER": "composer",
        # "PIP": "pypi",
        # "RUBYGEMS": "gem",
        "NPM": "npm",
        # "RUST": "cargo",
        # "GO": "golang",
    }

    def advisories_count(self):
        advisory_query = """
        query{
            securityVulnerabilities(first: 0, ecosystem: %s) {
                totalCount
            }
        }
        """
        advisory_counts = 0
        for ecosystem in self.package_type_by_github_ecosystem.keys():
            graphql_query = {"query": advisory_query % (ecosystem)}
            response = utils.fetch_github_graphql_query(graphql_query)
            advisory_counts += get_item(response, "data", "securityVulnerabilities", "totalCount")
        return advisory_counts

    def collect_advisories(self) -> Iterable[AdvisoryData]:

        # TODO: We will try to gather more info from GH API
        # Check https://github.com/nexB/vulnerablecode/issues/1039#issuecomment-1366458885
        # Check https://github.com/nexB/vulnerablecode/issues/645
        # set of all possible values of first '%s' = {'MAVEN','COMPOSER', 'NUGET', 'RUBYGEMS', 'PYPI', 'NPM', 'RUST'}
        # second '%s' is interesting, it will have the value '' for the first request,
        advisory_query = """
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
                            cwes(first: 10){
                                nodes {
                                    cweId
                                }
                            }
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
        for ecosystem, package_type in self.package_type_by_github_ecosystem.items():
            end_cursor_exp = ""
            while True:
                graphql_query = {"query": advisory_query % (ecosystem, end_cursor_exp)}
                response = utils.fetch_github_graphql_query(graphql_query)

                page_info = get_item(response, "data", "securityVulnerabilities", "pageInfo")
                end_cursor = get_item(page_info, "endCursor")
                if end_cursor:
                    end_cursor = f'"{end_cursor}"'
                    end_cursor_exp = f"after: {end_cursor}"

                yield from process_response(response, package_type=package_type)

                if not get_item(page_info, "hasNextPage"):
                    break


def get_purl(pkg_type: str, github_name: str, logger: Callable = None) -> Optional[PackageURL]:
    """
    Return a PackageURL by splitting the `github_name` using the `pkg_type`
    convention. Return None and log an error if we can not split or it is an
    unknown package type.

    For example::
    >>> expected = PackageURL(type='maven', namespace='org.apache.commons', name='commons-lang3')
    >>> assert get_purl("maven", "org.apache.commons:commons-lang3") == expected

    >>> expected = PackageURL(type="composer", namespace="foo", name="bar")
    >>> assert get_purl("composer", "foo/bar") == expected
    """
    if pkg_type == "maven":
        if ":" not in github_name:
            if logger:
                logger(f"get_purl: Invalid maven package name {github_name}", level=logging.ERROR)
            return
        ns, _, name = github_name.partition(":")
        return PackageURL(type=pkg_type, namespace=ns, name=name)

    if pkg_type in ("composer", "npm"):
        if "/" not in github_name:
            return PackageURL(type=pkg_type, name=github_name)
        vendor, _, name = github_name.partition("/")
        return PackageURL(type=pkg_type, namespace=vendor, name=name)

    if pkg_type in ("nuget", "pypi", "gem", "golang", "npm", "cargo"):
        return PackageURL(type=pkg_type, name=github_name)

    if logger:
        logger(f"get_purl: Unknown package type {pkg_type}", level=logging.ERROR)


def process_response(
    resp: dict, package_type: str, logger: Callable = None
) -> Iterable[AdvisoryData]:
    """
    Yield `AdvisoryData` by taking `resp` and `ecosystem` as input
    """
    vulnerabilities = get_item(resp, "data", "securityVulnerabilities", "edges") or []
    if not vulnerabilities:
        if logger:
            logger(
                f"No vulnerabilities found for package_type: {package_type!r} in response: {resp!r}",
                level=logging.ERROR,
            )
        return

    for vulnerability in vulnerabilities:
        aliases = []
        affected_packages = []
        github_advisory = get_item(vulnerability, "node")
        if not github_advisory:
            if logger:
                logger(f"No node found in {vulnerability!r}", level=logging.ERROR)
            continue

        advisory = get_item(github_advisory, "advisory")
        if not advisory:
            if logger:
                logger(f"No advisory found in {github_advisory!r}", level=logging.ERROR)
            continue

        summary = get_item(advisory, "summary") or ""

        references = get_item(advisory, "references") or []
        if references:
            urls = (ref["url"] for ref in references)
            references = [Reference.from_url(u) for u in urls]

        date_published = get_item(advisory, "publishedAt")
        if date_published:
            date_published = dateparser.parse(date_published)

        name = get_item(github_advisory, "package", "name")
        if name:
            purl = get_purl(pkg_type=package_type, github_name=name, logger=logger)
        if purl:
            affected_range = get_item(github_advisory, "vulnerableVersionRange")
            fixed_version = get_item(github_advisory, "firstPatchedVersion", "identifier")
            if affected_range:
                try:
                    affected_range = build_range_from_github_advisory_constraint(
                        package_type, affected_range
                    )
                except Exception as e:
                    if logger:
                        logger(
                            f"Could not parse affected range {affected_range!r} {e!r} \n {traceback_format_exc()}",
                            level=logging.ERROR,
                        )
                    affected_range = None
            if fixed_version:
                try:
                    fixed_version = RANGE_CLASS_BY_SCHEMES[package_type].version_class(
                        fixed_version
                    )
                except Exception as e:
                    if logger:
                        logger(
                            f"Invalid fixed version {fixed_version!r} {e!r} \n {traceback_format_exc()}",
                            level=logging.ERROR,
                        )
                    fixed_version = None
            if affected_range or fixed_version:
                affected_packages.append(
                    AffectedPackage(
                        package=purl,
                        affected_version_range=affected_range,
                        fixed_version=fixed_version,
                    )
                )
        identifiers = get_item(advisory, "identifiers") or []
        ghsa_id = ""
        severities = []
        for identifier in identifiers:
            value = identifier["value"]
            identifier_type = identifier["type"]
            aliases.append(value)
            # attach the GHSA with severity score
            if identifier_type == "GHSA":
                # Each Node has only one GHSA, hence exit after attaching
                # score to this GHSA
                ghsa_id = value
                for ref in references:
                    if ref.reference_id == value:
                        severity = get_item(advisory, "severity")
                        if severity:
                            severities = [
                                VulnerabilitySeverity(
                                    system=severity_systems.CVSS31_QUALITY,
                                    value=severity,
                                    url=ref.url,
                                )
                            ]

            elif identifier_type == "CVE":
                pass
            else:
                if logger:
                    logger(
                        f"Unknown identifier type {identifier_type!r} and value {value!r}",
                        level=logging.ERROR,
                    )

        weaknesses = get_cwes_from_github_advisory(advisory, logger)

        advisory_id = None

        aliases = sorted(dedupe(aliases))

        advisory_id = ghsa_id or aliases[0]

        aliases.remove(advisory_id)

        yield AdvisoryData(
            advisory_id=ghsa_id,
            aliases=aliases,
            summary=summary,
            references_v2=references,
            severities=severities,
            affected_packages=affected_packages,
            date_published=date_published,
            weaknesses=weaknesses,
            url=f"https://github.com/advisories/{ghsa_id}",
        )


def get_cwes_from_github_advisory(advisory, logger=None) -> List[int]:
    """
    Return the cwe-id list from advisory ex: [ 522 ]
    by extracting the cwe_list from advisory ex: [{'cweId': 'CWE-522'}]
    then remove the CWE- from string and convert it to integer 522 and Check if the CWE in CWE-Database
    """
    weaknesses = []
    db = Database()
    cwe_list = get_item(advisory, "cwes", "nodes") or []
    for cwe_item in cwe_list:
        cwe_string = get_item(cwe_item, "cweId")
        if cwe_string:
            cwe_id = get_cwe_id(cwe_string)
            try:
                db.get(cwe_id)
                weaknesses.append(cwe_id)
            except Exception as e:
                if logger:
                    logger(f"Invalid CWE id {e!r} \n {traceback_format_exc()}", level=logging.ERROR)
    return weaknesses
