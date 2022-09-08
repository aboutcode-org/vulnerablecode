#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import dataclasses
import logging
from typing import Iterable
from typing import List
from typing import Optional
from uuid import uuid4

from django.db.models.query import QuerySet
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.utils import classproperty

logger = logging.getLogger(__name__)

MAX_CONFIDENCE = 100


@dataclasses.dataclass(order=True)
class Inference:
    """
    This data class expresses the contract between improvers and the improve runner.

    Only inferences with highest confidence for one vulnerability <-> package
    relationship is to be inserted into the database
    """

    vulnerability_id: str = None
    aliases: Optional[List[str]] = dataclasses.field(default_factory=list)
    confidence: int = MAX_CONFIDENCE
    summary: Optional[str] = ""
    affected_purls: Optional[List[PackageURL]] = dataclasses.field(default_factory=list)
    fixed_purl: PackageURL = None
    references: List[Reference] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        if self.confidence > MAX_CONFIDENCE or self.confidence < 0:
            raise ValueError

        assert (
            self.vulnerability_id
            or self.aliases
            or self.summary
            or self.affected_purls
            or self.fixed_purl
            or self.references
        )

        versionless_purls = []
        purls = []
        if self.fixed_purl:
            purls.append(self.fixed_purl)
        if self.affected_purls:
            purls.extend(self.affected_purls)
        for purl in purls:
            if purl and not purl.version:
                versionless_purls.append(purl)

        assert (
            not versionless_purls
        ), f"Version-less purls are not supported in an Inference: {versionless_purls}"

    def to_dict(self):
        """
        Return a dict representation of this Inference
        """
        return {
            "vulnerability_id": self.vulnerability_id,
            "aliases": [alias for alias in self.aliases],
            "confidence": self.confidence,
            "summary": self.summary,
            "affected_purls": [affected_purl.to_dict() for affected_purl in self.affected_purls],
            "fixed_purl": self.fixed_purl.to_dict() if self.fixed_purl else None,
            "references": [ref.to_dict() for ref in self.references],
        }

    @classmethod
    def from_advisory_data(cls, advisory_data, confidence, fixed_purl, affected_purls=None):
        """
        Return an Inference object while keeping the same values as of advisory_data
        for vulnerability_id, summary and references
        """
        return cls(
            aliases=advisory_data.aliases,
            confidence=confidence,
            summary=advisory_data.summary,
            affected_purls=affected_purls or [],
            fixed_purl=fixed_purl,
            references=advisory_data.references,
        )


class Improver:
    """
    Improvers are responsible to improve already imported data by an importer.  An improver is
    required to override the ``interesting_advisories`` property method to return a QuerySet of
    ``Advisory`` objects. These advisories are then passed to ``get_inferences`` method which is
    responsible for returning an iterable of ``Inferences`` for that particular ``Advisory``
    """

    @classproperty
    def qualified_name(cls):
        """
        Fully qualified name prefixed with the module name of the improver used in logging.
        """
        return f"{cls.__module__}.{cls.__qualname__}"

    @property
    def interesting_advisories(self) -> QuerySet:
        """
        Return QuerySet for the advisories this improver is interested in.

        Subclasses must implement.
        """
        raise NotImplementedError

    def get_inferences(self, advisory_data: AdvisoryData) -> Iterable[Inference]:
        """
        Return an iterable of Inferences from the ``advisory data``.

        Subclasses must implement.
        """
        raise NotImplementedError
