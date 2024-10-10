#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from datetime import datetime
from datetime import timezone
from traceback import format_exc as traceback_format_exc
from typing import Iterable

from aboutcode.pipeline import BasePipeline
from aboutcode.pipeline import LoopProgress

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.models import Advisory
from vulnerabilities.pipes.advisory import import_advisory
from vulnerabilities.pipes.advisory import insert_advisory
from vulnerabilities.utils import classproperty

module_logger = logging.getLogger(__name__)


class VulnerableCodePipeline(BasePipeline):
    pipeline_id = None  # Unique Pipeline ID

    def log(self, message, level=logging.INFO):
        """Log the given `message` to the current module logger and execution_log."""
        now_local = datetime.now(timezone.utc).astimezone()
        timestamp = now_local.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        message = f"{timestamp} {message}"
        module_logger.log(level, message)
        self.append_to_log(message)

    @classproperty
    def pipeline_id(cls):
        """Return unique pipeline_id set in cls.pipeline_id"""

        if cls.pipeline_id is None or cls.pipeline_id == "":
            raise NotImplementedError("pipeline_id is not defined or is empty")
        return cls.pipeline_id


class VulnerableCodeBaseImporterPipeline(VulnerableCodePipeline):
    """
    Base importer pipeline for importing advisories.

    Uses:
        Subclass this Pipeline and implement ``advisories_count`` and ``collect_advisories`` method.
        Also override the ``steps`` and ``advisory_confidence`` as needed.
    """

    pipeline_id = None  # Unique Pipeline ID, this should be the name of pipeline module.
    license_url = None
    spdx_license_expression = None
    repo_url = None
    importer_name = None
    advisory_confidence = MAX_CONFIDENCE

    @classmethod
    def steps(cls):
        return (
            # Add step for downloading/cloning resource as required.
            cls.collect_and_store_advisories,
            cls.import_new_advisories,
            # Add step for removing downloaded/cloned resource as required.
        )

    def collect_advisories(self) -> Iterable[AdvisoryData]:
        """
        Yield AdvisoryData for importer pipeline.

        Populate the `self.collected_advisories_count` field and yield AdvisoryData
        """
        raise NotImplementedError

    def advisories_count(self) -> int:
        """
        Return the estimated AdvisoryData to be yielded by ``collect_advisories``.

        Used by ``collect_and_store_advisories`` to log the progress of advisory collection.
        """
        raise NotImplementedError

    def collect_and_store_advisories(self):
        collected_advisory_count = 0
        estimated_advisory_count = self.advisories_count()

        if estimated_advisory_count > 0:
            self.log(f"Collecting {estimated_advisory_count:,d} advisories")

        progress = LoopProgress(total_iterations=estimated_advisory_count, logger=self.log)
        for advisory in progress.iter(self.collect_advisories()):
            if _obj := insert_advisory(
                advisory=advisory,
                pipeline_id=self.pipeline_id,
                logger=self.log,
            ):
                collected_advisory_count += 1

        self.log(f"Successfully collected {collected_advisory_count:,d} advisories")

    def import_new_advisories(self):
        new_advisories = Advisory.objects.filter(
            created_by=self.pipeline_id,
            date_imported__isnull=True,
        )

        new_advisories_count = new_advisories.count()

        self.log(f"Importing {new_advisories_count:,d} new advisories")

        imported_advisory_count = 0
        progress = LoopProgress(total_iterations=new_advisories_count, logger=self.log)
        for advisory in progress.iter(new_advisories.paginated()):
            self.import_advisory(advisory=advisory)
            if advisory.date_imported:
                imported_advisory_count += 1

        self.log(f"Successfully imported {imported_advisory_count:,d} new advisories")

    def import_advisory(self, advisory: Advisory) -> int:
        try:
            import_advisory(
                advisory=advisory,
                pipeline_id=self.pipeline_id,
                confidence=self.advisory_confidence,
                logger=self.log,
            )
        except Exception as e:
            self.log(
                f"Failed to import advisory: {advisory!r} with error {e!r}:\n{traceback_format_exc()}",
                level=logging.ERROR,
            )
