#
# Copyright (c)  nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.
#
# Data Imported from https://github.com/pyupio/safety-db

import asyncio
import dataclasses
import re
import logging
from typing import Any
from typing import Iterable
from typing import Mapping
from typing import Set
from typing import Tuple

import requests
from dephell_specifier import RangeSpecifier
from packageurl import PackageURL
from schema import Or
from schema import Regex
from schema import Schema

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.data_source import Reference
from vulnerabilities.package_managers import PypiVersionAPI

logger = logging.getLogger(__name__)


def validate_schema(advisory_dict):

    scheme = [
        {
            "advisory": str,
            "cve": Or(None, str),
            "id": Regex(r"^pyup.io-\d"),
            "specs": list,
            "v": str,
        }
    ]

    Schema(scheme).validate(advisory_dict)


@dataclasses.dataclass
class SafetyDbConfiguration(DataSourceConfiguration):
    url: str
    etags: dict


class SafetyDbDataSource(DataSource):

    CONFIG_CLASS = SafetyDbConfiguration

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._api_response = self._fetch()

    def __enter__(self):
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

    def updated_advisories(self) -> Set[Advisory]:
        advisories = []

        for package_name in self._api_response:
            if package_name == "$meta":
                # This is the first entry in the data feed. It contains metadata of the feed.
                # Skip it.
                continue

            try:
                validate_schema(self._api_response[package_name])

            except Exception as e:
                logger.error(e)
                continue

            all_package_versions = self.versions.get(package_name)
            if not len(all_package_versions):
                # PyPi does not have data about this package, we skip these
                continue

            for advisory in self._api_response[package_name]:
                impacted_purls, resolved_purls = categorize_versions(
                    package_name, all_package_versions, advisory["specs"]
                )

                if advisory["cve"]:
                    # Check on advisory["cve"] instead of using `get` because it can have null value
                    cve_ids = re.findall(r"CVE-\d+-\d+", advisory["cve"])
                else:
                    cve_ids = [None]

                reference = [Reference(reference_id=advisory["id"])]

                for cve_id in cve_ids:
                    advisories.append(
                        Advisory(
                            vulnerability_id=cve_id,
                            summary=advisory["advisory"],
                            references=reference,
                            impacted_package_urls=impacted_purls,
                            resolved_package_urls=resolved_purls,
                        )
                    )

        return self.batch_advisories(advisories)

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


def categorize_versions(
    package_name: str,
    all_versions: Set[str],
    version_specs: Iterable[str],
) -> Tuple[Set[PackageURL], Set[PackageURL]]:
    """
    :return: impacted, resolved purls
    """
    impacted_versions, impacted_purls = set(), set()
    ranges = [RangeSpecifier(s) for s in version_specs]

    for version in all_versions:
        if any([version in r for r in ranges]):
            impacted_versions.add(version)

            impacted_purls.add(
                PackageURL(
                    name=package_name,
                    type="pypi",
                    version=version,
                )
            )

    resolved_purls = set()
    for version in all_versions - impacted_versions:
        resolved_purls.add(PackageURL(name=package_name, type="pypi", version=version))

    return impacted_purls, resolved_purls
