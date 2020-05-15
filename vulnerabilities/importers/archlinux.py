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
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Set
from urllib.request import urlopen

from packageurl import PackageURL
from schema import Regex, Schema, Or

from vulnerabilities.data_source import DataSource, DataSourceConfiguration, Advisory


def validate_schema(advisory_dict):
    scheme = {

        'advisories': list,
        'affected': str,
        'fixed': Or(None, str),
        'issues': [Regex(r'CVE-\d+-\d+')],
        'name': str,
        'packages': [str],
        'status': str,
        'ticket': object,
        'type': str,
        'severity': str,

    }

    Schema(scheme).validate(advisory_dict)


@dataclasses.dataclass
class ArchlinuxConfiguration(DataSourceConfiguration):
    archlinux_tracker_url: str


class ArchlinuxDataSource(DataSource):

    CONFIG_CLASS = ArchlinuxConfiguration

    def __enter__(self):
        self._api_response = self._fetch()

        for record in self._api_response:
            validate_schema(record)

    def updated_advisories(self) -> Set[Advisory]:
        advisories = []

        for record in self._api_response:
            advisories.extend(self._parse(record))

        while advisories:
            batch, advisories = advisories[:self.config.batch_size], advisories[self.config.batch_size:]
            yield set(batch)

    def _fetch(self) -> Iterable[Mapping]:
        return json.load(urlopen(self.config.archlinux_tracker_url))

    def _parse(self, record) -> List[Advisory]:
        advisories = []

        for cve_id in record['issues']:
            impacted_purls, resolved_purls = set(), set()
            for name in record['packages']:
                impacted_purls.add(PackageURL(
                    name=name,
                    type='pacman',
                    namespace='archlinux',
                    version=record['affected'],
                ))

                if record['fixed']:
                    resolved_purls.add(PackageURL(
                        name=name,
                        type='pacman',
                        namespace='archlinux',
                        version=record['fixed'],
                    ))

            advisories.append(Advisory(
                cve_id=cve_id,
                summary='',
                impacted_package_urls=impacted_purls,
                resolved_package_urls=resolved_purls,
                reference_urls=[f'https://security.archlinux.org/{a}' for a in record['advisories']],
            ))

        return advisories
