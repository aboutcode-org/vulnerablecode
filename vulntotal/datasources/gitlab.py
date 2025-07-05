#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import os
import shutil
import tarfile
from pathlib import Path
from typing import Iterable

import requests
import saneyaml
from fetchcode import fetch
from packageurl import PackageURL

from vulntotal.datasources.gitlab_api import fetch_gitlab_advisories_for_purl
from vulntotal.validator import DataSource
from vulntotal.validator import VendorData
from vulntotal.vulntotal_utils import gitlab_constraints_satisfied

logger = logging.getLogger(__name__)


class GitlabDataSource(DataSource):
    spdx_license_expression = "TODO"
    license_url = "TODO"

    def datasource_advisory(self, purl) -> Iterable[VendorData]:
        """
        Fetches advisories for a given purl from the GitLab API.

        Parameters:
            purl: A PackageURL instance representing the package to query.

        Yields:
            VendorData instance containing the advisory information for the package.
        """
        advisories = fetch_gitlab_advisories_for_purl(
            purl, self.supported_ecosystem(), get_casesensitive_slug
        )

        if advisories:
            return parse_interesting_advisories(advisories, purl)

    @classmethod
    def supported_ecosystem(cls):
        return {
            "composer": "packagist",
            "conan": "conan",
            "gem": "gem",
            "golang": "go",
            "maven": "maven",
            "npm": "npm",
            "nuget": "nuget",
            "pypi": "pypi",
        }


def get_casesensitive_slug(path, package_slug):
    payload = [
        {
            "operationName": "getPaginatedTree",
            "variables": {
                "projectPath": "gitlab-org/security-products/gemnasium-db",
                "ref": "master",
                "path": path,
                "nextPageCursor": "",
                "pageSize": 100,
            },
            "query": """
            fragment TreeEntry on Entry { 
                flatPath 
            } 
            query getPaginatedTree($projectPath: ID!, $path: String, $ref: String!, $nextPageCursor: String) { 
                project(fullPath: $projectPath) { 
                    repository { 
                        paginatedTree(path: $path, ref: $ref, after: $nextPageCursor) { 
                            pageInfo { 
                            endCursor
                            startCursor
                            hasNextPage 
                            } 
                        nodes { 
                            trees { 
                                nodes { 
                                    ...TreeEntry 
                                    } 
                                } 
                            } 
                        } 
                    } 
                } 
            } """,
        }
    ]
    url = "https://gitlab.com/api/graphql"
    has_next = True

    while has_next:
        response = requests.post(url, json=payload).json()
        paginated_tree = response[0]["data"]["project"]["repository"]["paginatedTree"]

        for slug in paginated_tree["nodes"][0]["trees"]["nodes"]:
            slug_flatpath = slug["flatPath"]
            if slug_flatpath.lower() == package_slug.lower():
                return slug_flatpath

            # If the namespace/subfolder contains multiple packages, then progressive transverse through folders tree
            if package_slug.lower().startswith(slug_flatpath.lower()):
                return get_casesensitive_slug(slug_flatpath, package_slug)

        payload[0]["variables"]["nextPageCursor"] = paginated_tree["pageInfo"]["endCursor"]
        has_next = paginated_tree["pageInfo"]["hasNextPage"]


def parse_interesting_advisories(advisories, purl) -> Iterable[VendorData]:
    """
    Parses advisories from YAML files in a given location that match a given version.

    Parameters:
        advisories: A list of advisory dictionaries fetched from the GitLab API.
        purl: PURL for the advisory.

    Yields:
        VendorData instance containing the advisory information for the package.
    """
    version = purl.version

    for advisory in advisories:
        affected_range = advisory.get("affected_range")
        if gitlab_constraints_satisfied(affected_range, version):
            yield VendorData(
                purl=PackageURL(purl.type, purl.namespace, purl.name),
                aliases=advisory.get("identifiers", []),
                affected_versions=[affected_range],
                fixed_versions=advisory.get("fixed_versions", []),
            )
