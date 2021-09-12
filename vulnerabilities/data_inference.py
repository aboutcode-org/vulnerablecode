import dataclasses
import logging
from typing import List
from typing import Optional

from packageurl import PackageURL

from vulnerabilities.data_source import Reference

logger = logging.getLogger(__name__)


class OverConfidenceError(ValueError):
    pass


class UnderConfidenceError(ValueError):
    pass


MAX_CONFIDENCE = 100


@dataclasses.dataclass(order=True)
class Inference:
    """
    This data class expresses the contract between data improvers and the improve runner.

    Only inferences with highest confidence for one vulnerability <-> package
    relationship is to be inserted into the database
    """

    vulnerability_id: str
    confidence: int
    summary: Optional[str] = None
    affected_packages: List[PackageURL] = dataclasses.field(default_factory=list)
    fixed_packages: List[PackageURL] = dataclasses.field(default_factory=list)
    references: List[Reference] = dataclasses.field(default_factory=list)

    def __post_init__(self):
        if self.confidence > MAX_CONFIDENCE:
            raise OverConfidenceError

        if self.confidence < 0:
            raise UnderConfidenceError


class Improver:
    """
    All improvers must inherit this class and implement the infer method to
    return new inferences for packages or vulnerabilities
    """

    def infer(self) -> List[Inference]:
        """
        Implement this method to generate and return Inferences
        """
        raise NotImplementedError
