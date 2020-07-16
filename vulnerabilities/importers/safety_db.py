#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.
#
# Data Imported from https://github.com/pyupio/safety-db
#
import dataclasses
import json
from typing import Any
from typing import Iterable
from typing import Mapping
from typing import Set
from typing import Tuple
from urllib.error import HTTPError
from urllib.request import urlopen

from dephell_specifier import RangeSpecifier
from packageurl import PackageURL
from schema import Or
from schema import Regex
from schema import Schema

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration
from vulnerabilities.data_source import VulnerabilityReferenceUnit


def validate_schema(advisory_dict):

    scheme = {
        str: [
            {
                "advisory": str,
                "cve": Or(None, Regex(r"CVE-\d+-\d+")),
                "id": Regex(r"^pyup.io-\d"),
                "specs": list,
                "v": str,
            }
        ]
    }

    Schema(scheme).validate(advisory_dict)


@dataclasses.dataclass
class SafetyDbConfiguration(DataSourceConfiguration):
    url: str


class SafetyDbDataSource(DataSource):

    CONFIG_CLASS = SafetyDbConfiguration

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._versions = VersionAPI()

    def __enter__(self):
        self._api_response = self._fetch()
        validate_schema(self._api_response)

    @property
    def versions(self):  # quick hack to make it patchable
        return self._versions

    def _fetch(self) -> Mapping[str, Any]:
        with urlopen(self.config.url) as response:
            return json.load(response)

    def updated_advisories(self) -> Set[Advisory]:
        advisories = []

        for package_name in self._api_response:
            all_package_versions = self.versions.get(package_name)
            if len(all_package_versions) == 0:
                # PyPi does not have data about this package, we skip these
                continue

            for advisory in self._api_response[package_name]:

                impacted_purls, resolved_purls = categorize_versions(
                    package_name, all_package_versions, advisory["specs"]
                )

                cve_ids = advisory.get("cve") or [""]

                # meaning if cve_ids is not [''] but either ['CVE-123'] or ['CVE-123, CVE-124']
                if len(cve_ids[0]):
                    cve_ids = [s.strip() for s in cve_ids.split(",")]

                reference = [VulnerabilityReferenceUnit(reference_id=advisory["id"])]

                for cve_id in cve_ids:
                    advisories.append(
                        Advisory(
                            cve_id=cve_id,
                            summary=advisory["advisory"],
                            vuln_references=reference,
                            impacted_package_urls=impacted_purls,
                            resolved_package_urls=resolved_purls,
                        )
                    )

        return self.batch_advisories(advisories)


def categorize_versions(
    package_name: str, all_versions: Set[str], version_specs: Iterable[str],
) -> Tuple[Set[PackageURL], Set[PackageURL]]:
    """
    :return: impacted, resolved purls
    """
    impacted_versions, impacted_purls = set(), set()
    ranges = [RangeSpecifier(s) for s in version_specs]

    for version in all_versions:
        if any([version in r for r in ranges]):
            impacted_versions.add(version)

            impacted_purls.add(PackageURL(name=package_name, type="pypi", version=version,))

    resolved_purls = set()
    for version in all_versions - impacted_versions:
        resolved_purls.add(PackageURL(name=package_name, type="pypi", version=version))

    return impacted_purls, resolved_purls


class VersionAPI:
    def __init__(self, cache: Mapping[str, Set[str]] = None):
        self.cache = cache or {}

    def get(self, package_name: str) -> Set[str]:
        package_name = package_name.strip()

        if package_name not in self.cache:
            releases = set()
            try:
                with urlopen(f"https://pypi.org/pypi/{package_name}/json") as response:
                    json_file = json.load(response)
                    releases = set(json_file["releases"])
            except HTTPError as e:
                if e.code == 404:
                    # PyPi does not have data about this package
                    pass
                else:
                    raise

            self.cache[package_name] = releases

        return self.cache[package_name]
