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

import logging
import os
import traceback
from datetime import datetime
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional

import pytz
import saneyaml
from dateutil import parser as dateparser
from django.db.models.query import QuerySet
from fetchcode.vcs import fetch_via_vcs
from packageurl import PackageURL
from univers.version_range import RANGE_CLASS_BY_SCHEMES
from univers.version_range import VersionRange
from univers.version_range import from_gitlab_native
from univers.versions import Version

from vulnerabilities.helpers import AffectedPackage as LegacyAffectedPackage
from vulnerabilities.helpers import get_affected_packages_by_patched_package
from vulnerabilities.helpers import nearest_patched_package
from vulnerabilities.helpers import resolve_version_range
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import UnMergeablePackageError
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory
from vulnerabilities.package_managers import VERSION_API_CLASSES_BY_PACKAGE_TYPE
from vulnerabilities.package_managers import GoproxyVersionAPI
from vulnerabilities.package_managers import VersionAPI
from vulnerabilities.package_managers import get_api_package_name

logger = logging.getLogger(__name__)


PURL_TYPE_BY_GITLAB_SCHEME = {
    "gem": "gem",
    "go": "golang",
    "maven": "maven",
    "npm": "npm",
    "nuget": "nuget",
    "pypi": "pypi",
    "packagist": "composer",
    # "conan": "conan",
}


GITLAB_SCHEME_BY_PURL_TYPE = {v: k for k, v in PURL_TYPE_BY_GITLAB_SCHEME.items()}


def fork_and_get_dir(url):
    """
    Fetch a clone of the gitlab repository at url and return the directory destination
    """
    return fetch_via_vcs(url).dest_dir


class ForkError(Exception):
    pass


class GitLabAPIImporter(Importer):
    spdx_license_expression = "MIT"
    license_url = "https://gitlab.com/gitlab-org/advisories-community/-/blob/main/LICENSE"
    gitlab_url = "git+https://gitlab.com/gitlab-org/advisories-community/"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        try:
            fork_directory = fork_and_get_dir(url=self.gitlab_url)
        except Exception as e:
            logger.error(f"Can't clone url {self.gitlab_url}")
            raise ForkError(self.gitlab_url) from e
        for root_dir in os.listdir(fork_directory):
            # skip well known files and directories that contain no advisory data
            if root_dir in ("ci", "CODEOWNERS", "README.md", "LICENSE", ".git"):
                continue
            if root_dir not in PURL_TYPE_BY_GITLAB_SCHEME:
                logger.error(f"Unknown package type: {root_dir}")
                continue
            for root, _, files in os.walk(os.path.join(fork_directory, root_dir)):
                for file in files:
                    yield parse_gitlab_advisory(file=os.path.join(root, file))


def get_purl(package_slug):
    """
    Return a PackageURL object from a package slug
    """
    parts = [p for p in package_slug.strip("/").split("/") if p]
    gitlab_scheme = parts[0]
    purl_type = PURL_TYPE_BY_GITLAB_SCHEME[gitlab_scheme]
    if gitlab_scheme == "go":
        name = "/".join(parts[1:])
        return PackageURL(type=purl_type, namespace=None, name=name)
    # if package slug is of the form:
    # "nuget/NuGet.Core"
    if len(parts) == 2:
        name = parts[1]
        return PackageURL(type=purl_type, name=name)
    # if package slug is of the form:
    # "nuget/github/user/abc/NuGet.Core"
    if len(parts) >= 3:
        name = parts[-1]
        namespace = "/".join(parts[1:-1])
        return PackageURL(type=purl_type, namespace=namespace, name=name)
    logger.error(f"get_purl: package_slug can not be parsed: {package_slug!r}")
    return


def extract_affected_packages(
    affected_version_range: VersionRange,
    fixed_versions: List[Version],
    purl: PackageURL,
) -> Iterable[AffectedPackage]:
    """
    Yield AffectedPackage objects, one for each fixed_version

    In case of gitlab advisory data we get a list of fixed_versions and a affected_version_range.
    Since we can not determine which package fixes which range.
    We store the all the fixed_versions with the same affected_version_range in the advisory.
    Later the advisory data is used to be infered in the GitLabBasicImprover.
    """
    for fixed_version in fixed_versions:
        yield AffectedPackage(
            package=purl,
            fixed_version=fixed_version,
            affected_version_range=affected_version_range,
        )


def parse_gitlab_advisory(file):
    """
    Parse a Gitlab advisory file and return an AdvisoryData or None.
    These files are YAML. There is a JSON schema documented at
    https://gitlab.com/gitlab-org/advisories-community/-/blob/main/ci/schema/schema.json

    Sample YAML file:
    ---
    identifier: "GMS-2018-26"
    package_slug: "packagist/amphp/http"
    title: "Incorrect header injection check"
    description: "amphp/http isn't properly protected against HTTP header injection."
    pubdate: "2018-03-15"
    affected_range: "<1.0.1"
    fixed_versions:
    - "v1.0.1"
    urls:
    - "https://github.com/amphp/http/pull/4"
    cwe_ids:
    - "CWE-1035"
    - "CWE-937"
    identifiers:
    - "GMS-2018-26"
    """
    with open(file, "r") as f:
        gitlab_advisory = saneyaml.load(f)
    if not isinstance(gitlab_advisory, dict):
        logger.error(f"parse_yaml_file: yaml_file is not of type `dict`: {gitlab_advisory!r}")
        return

    # refer to schema here https://gitlab.com/gitlab-org/advisories-community/-/blob/main/ci/schema/schema.json
    aliases = gitlab_advisory.get("identifiers")
    summary = ". ".join([gitlab_advisory.get("title"), gitlab_advisory.get("description")])
    urls = gitlab_advisory.get("urls")
    references = [Reference.from_url(u) for u in urls]
    date_published = dateparser.parse(gitlab_advisory.get("pubdate"))
    date_published = pytz.utc.localize(date_published)
    package_slug = gitlab_advisory.get("package_slug")
    purl: PackageURL = get_purl(package_slug=package_slug)
    if not purl:
        logger.error(f"parse_yaml_file: purl is not valid: {file!r} {package_slug!r}")
        return AdvisoryData(
            aliases=aliases,
            summary=summary,
            references=references,
            date_published=date_published,
        )
    affected_version_range = None
    fixed_versions = gitlab_advisory.get("fixed_versions") or []
    affected_range = gitlab_advisory.get("affected_range")
    gitlab_native_schemes = set(["pypi", "gem", "npm", "go", "packagist"])
    vrc: VersionRange = RANGE_CLASS_BY_SCHEMES[purl.type]
    gitlab_scheme = GITLAB_SCHEME_BY_PURL_TYPE[purl.type]
    try:
        if affected_range:
            if gitlab_scheme in gitlab_native_schemes:
                affected_version_range = from_gitlab_native(
                    gitlab_scheme=gitlab_scheme, string=affected_range
                )
            else:
                affected_version_range = vrc.from_native(affected_range)
    except Exception as e:
        logger.error(
            f"parse_yaml_file: affected_range is not parsable: {affected_range!r} type:{purl.type!r} error: {e!r}\n {traceback.format_exc()}"
        )

    parsed_fixed_versions = []
    for fixed_version in fixed_versions:
        try:
            fixed_version = vrc.version_class(fixed_version)
            parsed_fixed_versions.append(fixed_version)
        except Exception as e:
            logger.error(
                f"parse_yaml_file: fixed_version is not parsable`: {fixed_version!r} error: {e!r}\n {traceback.format_exc()}"
            )

    if parsed_fixed_versions:
        affected_packages = list(
            extract_affected_packages(
                affected_version_range=affected_version_range,
                fixed_versions=parsed_fixed_versions,
                purl=purl,
            )
        )
    else:
        if not affected_version_range:
            affected_packages = []
        else:
            affected_packages = [
                AffectedPackage(
                    package=purl,
                    affected_version_range=affected_version_range,
                )
            ]
    return AdvisoryData(
        aliases=aliases,
        summary=summary,
        references=references,
        date_published=date_published,
        affected_packages=affected_packages,
    )


class GitLabBasicImprover(Improver):
    """
    Get the nearest fixed_version and then resolve the version range with the help of all valid versions.
    Generate inference between all the affected packages and the fixed_version that fixes all those affected packages.

    In case of gitlab advisory data we get a list of fixed_versions and a affected_version_range.
    Since we can not determine which package fixes which range.
    """

    def __init__(self) -> None:
        self.versions_fetcher_by_purl: Mapping[str, VersionAPI] = {}

    @property
    def interesting_advisories(self) -> QuerySet:
        return Advisory.objects.filter(created_by=GitLabAPIImporter.qualified_name)

    def get_package_versions(
        self, package_url: PackageURL, until: Optional[datetime] = None
    ) -> List[str]:
        """
        Return a list of `valid_versions` for the `package_url`
        """
        api_name = get_api_package_name(purl=package_url)
        if not api_name:
            logger.error(f"Could not get versions for {package_url!r}")
            return []
        versions_fetcher = self.versions_fetcher_by_purl.get(package_url)
        if not versions_fetcher:
            versions_fetcher: VersionAPI = VERSION_API_CLASSES_BY_PACKAGE_TYPE[package_url.type]
            self.versions_fetcher_by_purl[package_url] = versions_fetcher()

        versions_fetcher = self.versions_fetcher_by_purl[package_url]

        self.versions_fetcher_by_purl[package_url] = versions_fetcher
        return versions_fetcher.get_until(package_name=api_name, until=until).valid_versions

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        """
        Yield Inferences for the given advisory data
        """
        if not advisory_data.affected_packages:
            return iter([])
        try:
            purl, affected_version_ranges, _ = AffectedPackage.merge(
                advisory_data.affected_packages
            )
        except UnMergeablePackageError:
            logger.error(f"Cannot merge with different purls {advisory_data.affected_packages!r}")
            return iter([])

        pkg_type = purl.type
        pkg_namespace = purl.namespace
        pkg_name = purl.name
        if purl.type == "golang":
            # Problem with the Golang and Go that they provide full path
            # FIXME: We need to get the PURL subpath for Go module
            versions_fetcher = self.versions_fetcher_by_purl.get(purl)
            if not versions_fetcher:
                versions_fetcher = GoproxyVersionAPI()
                self.versions_fetcher_by_purl[purl] = versions_fetcher
            pkg_name = versions_fetcher.module_name_by_package_name.get(pkg_name, pkg_name)

        valid_versions = self.get_package_versions(
            package_url=purl, until=advisory_data.date_published
        )
        for affected_version_range in affected_version_ranges:
            aff_vers, unaff_vers = resolve_version_range(
                affected_version_range=affected_version_range,
                package_versions=valid_versions,
                ignorable_versions=[],
            )
            affected_purls = [
                PackageURL(type=pkg_type, namespace=pkg_namespace, name=pkg_name, version=version)
                for version in aff_vers
            ]

            unaffected_purls = [
                PackageURL(type=pkg_type, namespace=pkg_namespace, name=pkg_name, version=version)
                for version in unaff_vers
            ]

            affected_packages: List[LegacyAffectedPackage] = nearest_patched_package(
                vulnerable_packages=affected_purls, resolved_packages=unaffected_purls
            )

            for (
                fixed_package,
                affected_packages,
            ) in get_affected_packages_by_patched_package(affected_packages).items():
                yield Inference.from_advisory_data(
                    advisory_data,  # We are getting all valid versions to get this inference
                    confidence=100,
                    affected_purls=affected_packages,
                    fixed_purl=fixed_package,
                )
