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

        :param purl: A PackageURL object representing the package to query.
        :return: An iterable of VendorData objects containing the advisory information.
        """
        package_slug = get_package_slug(purl)
        location = download_subtree(package_slug, speculative_execution=True)
        if location:
            interesting_advisories = parse_interesting_advisories(
                location, purl.version, delete_download=True
            )
            return interesting_advisories
        clear_download(location)
        path = self.supported_ecosystem()[purl.type]
        case_sensitive_package_slug = get_case_sensitive_slug(path, package_slug)
        location = download_subtree(case_sensitive_package_slug)

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


def get_package_slug(purl):
    """
    Constructs a package slug from a given purl.

    :param purl: A PackageURL object representing the package to query.
    :return: A string representing the package slug, or None if the purl type is not supported.
    """
    supported_ecosystem = GitlabDataSource.supported_ecosystem()

    if purl.type not in supported_ecosystem:
        return

    ecosystem = supported_ecosystem[purl.type]
    package_name = purl.name

    if purl.type in ("maven", "composer", "golang"):
        package_name = f"{purl.namespace}/{purl.name}"

    return f"{ecosystem}/{package_name}"


def download_subtree(package_slug: str, speculative_execution=False):
    """
    Downloads and extracts a tar file from a given package slug.

    :param package_slug: A string representing the package slug to query.
    :param speculative_execution: A boolean indicating whether to log errors or not.
    :return: A Path object representing the extracted location, or None if an error occurs.
    """
    url = f"https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/archive/master/gemnasium-db-master.tar.gz?path={package_slug}"
    response = fetch(url)
    with contextlib.suppress(FileNotFoundError):
        if os.path.getsize(response.location) > 0:
            extracted_location = Path(response.location).parent.joinpath(
                "temp_vulntotal_gitlab_datasource"
            )
            with tarfile.open(response.location, "r") as file_obj:
                file_obj.extractall(extracted_location)
            os.remove(response.location)
            return extracted_location
        if speculative_execution is False:
            logger.error(f"{package_slug} doesn't exist")
        os.remove(response.location)


def clear_download(location):
    """
    Deletes a directory and its contents.

    :param location: A Path object representing the directory to delete.
    """
    if location:
        shutil.rmtree(location)


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
    url = 'https://gitlab.com/api/graphql'
    has_next = True

    while has_next:
        response = requests.post(url, json=payload).json()
        paginated_tree = response[0]['data']['project']['repository']['paginatedTree']

        for slug in paginated_tree['nodes'][0]['trees']['nodes']:
            slug_flatpath = slug['flatPath']
            if slug_flatpath.lower() == package_slug.lower():
                return slug_flatpath

            # If the namespace/subfolder contains multiple packages, then progressive transverse through folders tree
            if package_slug.lower().startswith(slug_flatpath.lower()):
                return get_gitlab_style_slug(slug_flatpath, package_slug)

        payload[0]['variables']['nextPageCursor'] = paginated_tree['pageInfo']['endCursor']
        has_next = paginated_tree['pageInfo']['hasNextPage']


def parse_interesting_advisories(location, version, delete_download=False) -> Iterable[VendorData]:
    """
    Parses advisories from YAML files in a given location that match a given version.

    :param location: A Path object representing the location of the YAML files.
    :param version: A string representing the version to check against the affected range.
    :param delete_download: A boolean indicating whether to delete the downloaded files after parsing.
    :return: An iterable of VendorData objects containing the advisory information.
    """
    path = Path(location)
    pattern = '**/*.yml'
    files = [p for p in path.glob(pattern) if p.is_file()]
    for file in sorted(files):
        with open(file) as f:
            gitlab_advisory = saneyaml.load(f)
        affected_range = gitlab_advisory['affected_range']
        if gitlab_constraints_satisfied(affected_range, version):
            yield VendorData(
                aliases=gitlab_advisory['identifiers'],
                affected_versions=[affected_range],
                fixed_versions=gitlab_advisory['fixed_versions'],
            )
    if delete_download:
        clear_download(location)