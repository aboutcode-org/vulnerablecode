import dataclasses
import logging
from typing import List

from vulnerabilities.data_source import AdvisoryData

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

    Source and confidence correspond to the improver, only inferences with highest confidence
    for one vulnerability <-> package relationship is to be inserted into the database
    """

    advisory_data: AdvisoryData
    source: str
    confidence: int

    def __post_init__(self):
        if self.confidence > MAX_CONFIDENCE:
            raise OverConfidenceError

        if self.confidence < 0:
            raise UnderConfidenceError


class Improver:
    """
    All improvers should inherit this class and implement inferences method to return
    new inferences for a package or vulnerability
    """

    def inferences(self):
        raise NotImplementedError
