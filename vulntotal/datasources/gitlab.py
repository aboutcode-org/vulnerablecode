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
        package_slug = get_package_slug(purl)
        directory_files = fetch_directory_contents(package_slug)
        if not directory_files:
            path = self.supported_ecosystem()[purl.type]
            casesensitive_package_slug = get_casesensitive_slug(path, package_slug)
            directory_files = fetch_directory_contents(casesensitive_package_slug)

        if directory_files:
            yml_files = [file for file in directory_files if file["name"].endswith(".yml")]

            interesting_advisories = parse_interesting_advisories(yml_files, purl)
            return interesting_advisories

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


def fetch_directory_contents(package_slug):
    url = f"https://gitlab.com/api/v4/projects/12006272/repository/tree?path={package_slug}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()


def fetch_yaml(file_path):
    response = requests.get(
        f"https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/raw/master/{file_path}"
    )
    if response.status_code == 200:
        return response.text


def get_package_slug(purl):
    """
    Constructs a package slug from a given purl.

    Parameters:
        purl: A PackageURL instance representing the package to query.

    Returns:
        A string representing the package slug, or None if the purl type is not supported by GitLab.
    """
    supported_ecosystem = GitlabDataSource.supported_ecosystem()

    if purl.type not in supported_ecosystem:
        return

    ecosystem = supported_ecosystem[purl.type]
    package_name = purl.name

    if purl.type in ("maven", "composer", "golang"):
        package_name = f"{purl.namespace}/{purl.name}"

    return f"{ecosystem}/{package_name}"


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


def parse_interesting_advisories(yml_files, purl) -> Iterable[VendorData]:
    """
    Parses advisories from YAML files in a given location that match a given version.

    Parameters:
        yml_files: An array having the paths of yml files to parse.
        purl: PURL for the advisory.

    Yields:
        VendorData instance containing the advisory information for the package.
    """
    version = purl.version

    for file in yml_files:
        yml_data = fetch_yaml(file["path"])
        gitlab_advisory = saneyaml.load(yml_data)
        affected_range = gitlab_advisory["affected_range"]
        if gitlab_constraints_satisfied(affected_range, version):
            yield VendorData(
                purl=PackageURL(purl.type, purl.namespace, purl.name),
                aliases=gitlab_advisory["identifiers"],
                affected_versions=[affected_range],
                fixed_versions=gitlab_advisory["fixed_versions"],
            )
