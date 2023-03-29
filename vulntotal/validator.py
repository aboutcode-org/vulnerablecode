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

from packageurl import PackageURL


@dataclasses.dataclass(order=True)
class VendorData:
    purl: PackageURL
    aliases: List[str] = dataclasses.field(default_factory=list)
    affected_versions: List[str] = dataclasses.field(default_factory=list)
    fixed_versions: List[str] = dataclasses.field(default_factory=list)

    def to_dict(self):
        return {
            "purl": str(self.purl),
            "affected_versions": self.affected_versions,
            "fixed_versions": self.fixed_versions,
            "aliases": self.aliases,
        }


class InvalidCVEError(Exception):
    def __init__(self, message="CVE identifier must start with 'CVE-'"):
        self.message = message
        super().__init__(self.message)


class DataSource:
    def __init__(self):
        self._raw_dump = []

    def datasource_advisory(self, purl: PackageURL) -> Iterable[VendorData]:
        """
        Yield VendorData object for crossponding PURL.
        """
        return NotImplementedError

    def datasource_advisory_from_cve(self, cve: str) -> Iterable[VendorData]:
        """
        Yield VendorData objects for a given CVE identifier.
        """
        if not cve.upper().startswith("CVE-"):
            raise InvalidCVEError

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
