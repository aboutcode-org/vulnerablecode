import dataclasses
import logging
from vulnerabilities.data_source import Advisory

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
    """
    advisory: Advisory
    source: str
    confidence: int

    def __post_init__(self):
        if self.confidence > MAX_CONFIDENCE:
            raise OverConfidenceError

        if self.confidence < 0:
            raise UnderConfidenceError

class Improver:
    """
    All improvers should inherit this class and implement updated_inferences method to return
    new inferences for a package or vulnerability
    """
    def updated_inferences(self):
        raise NotImplementedError
