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

import dataclasses
import json
from typing import Iterable
from typing import List

from vulnerabilities.utils import classproperty


@dataclasses.dataclass(order=True)
class VendorData:
    aliases: List[str] = dataclasses.field(default_factory=list)
    affected_versions: List[str] = dataclasses.field(default_factory=list)
    fixed_versions: List[str] = dataclasses.field(default_factory=list)

    def to_dict(self):
        return {
            "affected_versions": self.affected_versions,
            "fixed_versions": self.fixed_versions,
            "aliases": self.aliases,
        }


class Validator:
    _raw_dump = []

    def validator_advisory(self, purl) -> Iterable[VendorData]:
        """
        Yield VendorData object corresponding to vendor
        """
        return NotImplementedError

    @property
    def raw_dump(self):
        return self._raw_dump
