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
import dataclasses
import json
from typing import Any
from typing import List
from typing import Mapping
from typing import Set
from urllib.request import urlopen

from packageurl import PackageURL
from schema import Optional
from schema import Or
from schema import Regex
from schema import Schema

from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import DataSource
from vulnerabilities.data_source import DataSourceConfiguration


def validate_schema(advisory_dict):

    deb_versions = ['bullseye', 'buster', 'buster-security', 'sid',
                    'stretch', 'stretch-security', 'jessie', 'jessie-security']
    scheme = {
        str:
            {
                Or(Regex(r"CVE-\d+-\d+"), Regex(r"TEMP-.+-.+")):
                {
                    'releases':
                    {
                        Or(*deb_versions):
                        {
                            'repositories':
                            {
                                Or(*deb_versions): str
                            },
                            'status': str,
                            'urgency': str,
                            Optional('fixed_version'): str,
                            Optional(str): object,
                        }

                    },
                    Optional('description'): str,
                    Optional('debianbug'): int,
                    Optional(str): object,
                }
            }

    }

    Schema(scheme).validate(advisory_dict)


@dataclasses.dataclass
class DebianConfiguration(DataSourceConfiguration):
    debian_tracker_url: str


class DebianDataSource(DataSource):

    CONFIG_CLASS = DebianConfiguration

    def __enter__(self):
        self._api_response = self._fetch()
        validate_schema(self._api_response)

    def updated_advisories(self) -> Set[Advisory]:
        advisories = []

        for pkg_name, records in self._api_response.items():
            advisories.extend(self._parse(pkg_name, records))

        return self.batch_advisories(advisories)

    def _fetch(self) -> Mapping[str, Any]:
        with urlopen(self.config.debian_tracker_url) as response:
            return json.load(response)

    def _parse(self, pkg_name: str, records: Mapping[str, Any]) -> List[Advisory]:
        advisories = []

        for cve_id, record in records.items():
            impacted_purls, resolved_purls = set(), set()

            for release_name, release_record in record['releases'].items():
                if not release_record.get('repositories', {}).get(release_name):
                    continue

                purl = PackageURL(
                    name=pkg_name,
                    type='deb',
                    namespace='debian',
                    version=release_record['repositories'][release_name],
                    qualifiers={'distro': release_name},
                )

                if release_record.get('status', '') == 'resolved':
                    resolved_purls.add(purl)
                else:
                    impacted_purls.add(purl)

                if 'fixed_version' in release_record:
                    resolved_purls.add(PackageURL(
                        name=pkg_name,
                        type='deb',
                        namespace='debian',
                        version=release_record['fixed_version'],
                        qualifiers={'distro': release_name},
                    ))

            reference_urls = []
            debianbug = record.get('debianbug')
            if debianbug:
                bug_url = f'https://bugs.debian.org/cgi-bin/bugreport.cgi?bug={debianbug}'
                reference_urls.append(bug_url)

            advisories.append(Advisory(
                cve_id=cve_id,
                summary=record.get('description', ''),
                impacted_package_urls=impacted_purls,
                resolved_package_urls=resolved_purls,
                reference_urls=reference_urls,
            ))

        return advisories
