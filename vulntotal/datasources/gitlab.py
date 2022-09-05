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


import json
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
        package_slug = get_package_slug(purl)
        location = download_subtree(package_slug, speculative_execution=True)
        if not location:
            clear_download(location)
            path = self.supported_ecosystem()[purl.type]
            casesensitive_package_slug = get_casesensitive_slug(path, package_slug)
            location = download_subtree(casesensitive_package_slug)
        if location:
            interesting_advisories = parse_interesting_advisories(location, purl.version, delete_download=True)
            return interesting_advisories
        clear_download(location)

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
    supported_ecosystem = GitlabDataSource.supported_ecosystem()

    if purl.type not in supported_ecosystem:
        return

    ecosystem = supported_ecosystem[purl.type]
    package_name = purl.name

    if purl.type in ("maven", "composer", "golang"):
        package_name = f"{purl.namespace}/{purl.name}"

    return f"{ecosystem}/{package_name}"


def download_subtree(package_slug: str, speculative_execution=False):
    url = f"https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/archive/master/gemnasium-db-master.tar.gz?path={package_slug}"
    response = fetch(url)
    if os.path.getsize(response.location) > 0:
        extracted_location = Path(response.location).parent.joinpath(
            "temp_vulntotal_gitlab_datasource"
        )
        with tarfile.open(response.location, "r") as file_obj:
            file_obj.extractall(extracted_location)
        os.remove(response.location)
        return extracted_location
    if not speculative_execution:
        logger.error(f"{package_slug} doesn't exist")
    os.remove(response.location)


def clear_download(location):
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
    url = "https://gitlab.com/api/graphql"
    hasnext = True

    while hasnext:
        response = requests.post(url, json=payload).json()
        paginated_tree = response[0]["data"]["project"]["repository"]["paginatedTree"]

        for slug in paginated_tree["nodes"][0]["trees"]["nodes"]:
            if slug["flatPath"].lower() == package_slug.lower():
                return slug["flatPath"]

            # If the namespace/subfolder contains multiple packages, then progressive transverse through folders tree
            if package_slug.lower().startswith(slug["flatPath"].lower()):
                return get_gitlab_style_slug(slug["flatPath"], package_slug)

        payload[0]["variables"]["nextPageCursor"] = paginated_tree["pageInfo"]["endCursor"]
        hasnext = paginated_tree["pageInfo"]["hasNextPage"]


def parse_interesting_advisories(location, version, delete_download=False) -> Iterable[VendorData]:
    path = Path(location)
    glob = "**/*.yml"
    files = (p for p in path.glob(glob) if p.is_file())
    for file in sorted(files):
        with open(file) as f:
            gitlab_advisory = saneyaml.load(f)
        if gitlab_constraints_satisfied(gitlab_advisory["affected_range"], version):
            yield VendorData(
                aliases=gitlab_advisory["identifiers"],
                affected_versions=[gitlab_advisory["affected_range"]],
                fixed_versions=gitlab_advisory["fixed_versions"],
            )
    if delete_download:
        clear_download(location)
