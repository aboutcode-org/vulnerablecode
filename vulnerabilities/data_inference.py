import dataclasses
import logging
from typing import List
from typing import Optional
from uuid import uuid4

from packageurl import PackageURL
from django.db.models.query import QuerySet

from vulnerabilities.data_source import Reference
from vulnerabilities.data_source import AdvisoryData

logger = logging.getLogger(__name__)

MAX_CONFIDENCE = 100


@dataclasses.dataclass(order=True)
class Inference:
    """
    This data class expresses the contract between data improvers and the improve runner.

    If a vulnerability_id is present then:
        summary or affected_purls or fixed_purl or references must be present
    otherwise
        either affected_purls or fixed_purl or references should be present and
        a VULCOID will be assigned as the vulnerability_id

    Only inferences with highest confidence for one vulnerability <-> package
    relationship is to be inserted into the database
    """

    vulnerability_id: str
    confidence: int = MAX_CONFIDENCE
    summary: Optional[str] = None
    affected_purls: List[PackageURL] = dataclasses.field(default_factory=list)
    fixed_purl: PackageURL = dataclasses.field(default_factory=list)
    references: List[Reference] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        if self.confidence > MAX_CONFIDENCE or self.confidence < 0:
            raise ValueError

        if self.vulnerability_id:
            assert self.summary or self.affected_purls or self.fixed_purl or self.references
        else:
            # TODO: Maybe only having summary
            assert self.affected_purls or self.fixed_purl or self.references
            self.vulnerability_id = self.generate_vulcoid()

        versionless_purls = []
        for purl in self.affected_purls + [self.fixed_purl]:
            if not purl.version:
                versionless_purls.append(purl)

        assert (
            not versionless_purls
        ), f"Version-less purls are not supported in an Inference: {versionless_purls}"

    @staticmethod
    def generate_vulcoid():
        return f"VULCOID-{uuid4()}"


class Improver:
    """
    Improvers are responsible to improve the already imported data by a datasource.
    Inferences regarding the data could be generated based on multiple factors.
    """

    @property
    def interesting_advisories(self) -> QuerySet:
        """
        Return QuerySet for the advisories this improver is interested in
        """
        raise NotImplementedError

    def get_inferences(self, advisory_data: AdvisoryData) -> List[Inference]:
        """
        Generate and return Inferences for the given advisory data
        """
        raise NotImplementedError

    def __repr__(self):
        """
        Fully qualified name prefixed with the module name of the improver
        used in logging.
        """
        return f"{self.__module__}.{self.__class__.__qualname__}"
