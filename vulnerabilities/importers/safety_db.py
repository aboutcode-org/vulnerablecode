#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import asyncio
import logging
import re
from typing import Any
from typing import Iterable
from typing import Mapping
from typing import Set
from typing import Tuple

import requests
from packageurl import PackageURL
from univers.version_range import PypiVersionRange
from univers.versions import InvalidVersion
from univers.versions import PypiVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.package_managers import PypiVersionAPI
from vulnerabilities.utils import nearest_patched_package

logger = logging.getLogger(__name__)


class SafetyDbImporter(Importer):
    def __enter__(self):
        self._api_response = self._fetch()
        self._versions = PypiVersionAPI()
        self.set_api(self.collect_packages())

    @property
    def versions(self):  # quick hack to make it patchable
        return self._versions

    def set_api(self, packages):
        asyncio.run(self._versions.load_api(packages))

    def _fetch(self) -> Mapping[str, Any]:
        if self.create_etag(self.config.url):
            return requests.get(self.config.url).json()
        return []

    def collect_packages(self):
        return {pkg for pkg in self._api_response}

    def updated_advisories(self) -> Set[AdvisoryData]:
        for package_name in self._api_response:
            if package_name == "$meta" or package_name == "cumin":
                # This is the first entry in the data feed. It contains metadata of the feed.
                # Skip it. The 'cumin' entry is wrong
                continue

            all_package_versions = self.versions.get(package_name).valid_versions
            if not len(all_package_versions):
                # PyPi does not have data about this package, we skip these
                continue

            for advisory in self._api_response[package_name]:
                if advisory["cve"]:
                    # Check on advisory["cve"] instead of using `get` because it can have null value
                    cve_ids = re.findall(r"CVE-\d+-\d+", advisory["cve"])
                else:
                    continue

                impacted_purls, resolved_purls = categorize_versions(
                    package_name, all_package_versions, advisory["specs"]
                )

                reference = [Reference(reference_id=advisory["id"])]
                advisories = []
                for cve_id in cve_ids:
                    advisories.append(
                        AdvisoryData(
                            vulnerability_id=cve_id,
                            summary=advisory["advisory"],
                            references=reference,
                            affected_packages=nearest_patched_package(
                                impacted_purls, resolved_purls
                            ),
                        )
                    )

                yield advisories

    # FIXME: This is duplicate code. Use the the helper instead.
    def create_etag(self, url):
        etag = requests.head(url).headers.get("ETag")
        if not etag:
            # Kind of inaccurate to return True since etag is
            # not created
            return True
        elif url in self.config.etags:
            if self.config.etags[url] == etag:
                return False
        self.config.etags[url] = etag
        return True


# FIXME: This function is horribly named incorretly.
def categorize_versions(
    package_name: str,
    all_versions: Set[str],
    version_specs: Iterable[str],
) -> Tuple[Set[PackageURL], Set[PackageURL]]:
    """
    :return: impacted, resolved purls
    """
    impacted_versions, impacted_purls = set(), []
    vurl_specs = []
    for version_spec in version_specs:
        vurl_specs.append(PypiVersionRange.from_native(version_spec))

    invalid_versions = set()
    for version in all_versions:
        try:
            version_object = PypiVersion(version)
        except InvalidVersion:
            invalid_versions.add(version)
            continue

        if any([version_object in vurl_spec for vurl_spec in vurl_specs]):
            impacted_versions.add(version)
            impacted_purls.append(
                PackageURL(
                    name=package_name,
                    type="pypi",
                    version=version,
                )
            )

    resolved_purls = []
    all_versions -= invalid_versions
    for version in all_versions - impacted_versions:
        resolved_purls.append(PackageURL(name=package_name, type="pypi", version=version))
    return impacted_purls, resolved_purls
