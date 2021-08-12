from datetime import datetime
import dataclasses
import logging

logger = logging.getLogger(__name__)

class ImproveRunner:
    """
    The ImproveRunner is responsible to improve the already imported data by a datasource.
    Inferences regarding the data could be generated based on multiple factors.
    All the inferences consist of a confidence score whose threshold could be tuned in user
    settings (.env file)
    """
    def __init__(self, improver):
        self.improver = improver

    def run(self) -> None:
        logger.info("Improving using %s.", self.improver.__module__)
        inferences = self.improver.updated_inferences()
        process_inferences(inferences)
        logger.info("Finished improving using %s.", self.improver.__module__)


def process_inferences(inferences):
    ...
