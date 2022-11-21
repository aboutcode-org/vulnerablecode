#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import dataclasses
from typing import Iterable
from typing import List


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


class DataSource:
    def __init__(self):
        self._raw_dump = []

    def datasource_advisory(self, purl) -> Iterable[VendorData]:
        """
        Yield VendorData object corresponding to DataSource
        """
        return NotImplementedError

    @classmethod
    def supported_ecosystem(cls):
        """
        Return dictionary containing supported ecosystem
        {
           "PURL equivalent ecosystem" : "DataSource ecosystem",
        }
        """
        return NotImplementedError

    @property
    def raw_dump(self):
        return self._raw_dump
