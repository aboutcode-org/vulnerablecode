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
from typing import Optional

from dateutil import parser as dateparser
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import build_range_from_github_advisory_constraint

from vulnerabilities import severity_systems
from vulnerabilities import utils
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.utils import dedupe
from vulnerabilities.utils import get_item

logger = logging.getLogger(__name__)


PACKAGE_TYPE_BY_GITHUB_ECOSYSTEM = {
    "MAVEN": "maven",
    "NUGET": "nuget",
    "COMPOSER": "composer",
    "PIP": "pypi",
    "RUBYGEMS": "gem",
    "NPM": "npm",
    "GO": "golang",
}

GITHUB_ECOSYSTEM_BY_PACKAGE_TYPE = {
    value: key for (key, value) in PACKAGE_TYPE_BY_GITHUB_ECOSYSTEM.items()
}

# TODO: We will try to gather more info from GH API
# Check https://github.com/nexB/vulnerablecode/issues/1039#issuecomment-1366458885
# Check https://github.com/nexB/vulnerablecode/issues/645
# set of all possible values of first '%s' = {'MAVEN','COMPOSER', 'NUGET', 'RUBYGEMS', 'PYPI', 'NPM'}
# second '%s' is interesting, it will have the value '' for the first request,
GRAPHQL_QUERY_TEMPLATE = """
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


class GitHubAPIImporter(Importer):
    spdx_license_expression = "CC-BY-4.0"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        for ecosystem, package_type in PACKAGE_TYPE_BY_GITHUB_ECOSYSTEM.items():
            end_cursor_exp = ""
            while True:
                graphql_query = {"query": GRAPHQL_QUERY_TEMPLATE % (ecosystem, end_cursor_exp)}
                response = utils.fetch_github_graphql_query(graphql_query)

                page_info = get_item(response, "data", "securityVulnerabilities", "pageInfo")
                end_cursor = get_item(page_info, "endCursor")
                if end_cursor:
                    end_cursor = f'"{end_cursor}"'
                    end_cursor_exp = f"after: {end_cursor}"

                yield from process_response(response, package_type=package_type)

                if not get_item(page_info, "hasNextPage"):
                    break


def get_purl(pkg_type: str, github_name: str) -> Optional[PackageURL]:
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
            logger.error(f"get_purl: Invalid maven package name {github_name}")
            return
        ns, _, name = github_name.partition(":")
        return PackageURL(type=pkg_type, namespace=ns, name=name)

    if pkg_type in ("composer", "npm"):
        if "/" not in github_name:
            return PackageURL(type=pkg_type, name=github_name)
        vendor, _, name = github_name.partition("/")
        return PackageURL(type=pkg_type, namespace=vendor, name=name)

    if pkg_type in ("nuget", "pypi", "gem", "golang", "npm"):
        return PackageURL(type=pkg_type, name=github_name)

    logger.error(f"get_purl: Unknown package type {pkg_type}")


def process_response(resp: dict, package_type: str) -> Iterable[AdvisoryData]:
    """
    Yield `AdvisoryData` by taking `resp` and `ecosystem` as input
    """
    vulnerabilities = get_item(resp, "data", "securityVulnerabilities", "edges") or []
    if not vulnerabilities:
        logger.error(
            f"No vulnerabilities found for package_type: {package_type!r} in response: {resp!r}"
        )
        return

    for vulnerability in vulnerabilities:
        aliases = []
        affected_packages = []
        github_advisory = get_item(vulnerability, "node")
        if not github_advisory:
            logger.error(f"No node found in {vulnerability!r}")
            continue

        advisory = get_item(github_advisory, "advisory")
        if not advisory:
            logger.error(f"No advisory found in {github_advisory!r}")
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
            purl = get_purl(pkg_type=package_type, github_name=name)
        if purl:
            affected_range = get_item(github_advisory, "vulnerableVersionRange")
            fixed_version = get_item(github_advisory, "firstPatchedVersion", "identifier")
            if affected_range:
                try:
                    affected_range = build_range_from_github_advisory_constraint(
                        package_type, affected_range
                    )
                except Exception as e:
                    logger.error(f"Could not parse affected range {affected_range!r} {e!r}")
                    affected_range = None
            if fixed_version:
                try:
                    fixed_version = RANGE_CLASS_BY_SCHEMES[package_type].version_class(
                        fixed_version
                    )
                except Exception as e:
                    logger.error(f"Invalid fixed version {fixed_version!r} {e!r}")
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
        for identifier in identifiers:
            value = identifier["value"]
            identifier_type = identifier["type"]
            aliases.append(value)
            # attach the GHSA with severity score
            if identifier_type == "GHSA":
                # Each Node has only one GHSA, hence exit after attaching
                # score to this GHSA
                for ref in references:
                    if ref.reference_id == value:
                        severity = get_item(advisory, "severity")
                        if severity:
                            ref.severities = [
                                VulnerabilitySeverity(
                                    system=severity_systems.CVSS31_QUALITY,
                                    value=severity,
                                )
                            ]

            elif identifier_type == "CVE":
                pass
            else:
                logger.error(f"Unknown identifier type {identifier_type!r} and value {value!r}")

        yield AdvisoryData(
            aliases=sorted(dedupe(aliases)),
            summary=summary,
            references=references,
            affected_packages=affected_packages,
            date_published=date_published,
        )
