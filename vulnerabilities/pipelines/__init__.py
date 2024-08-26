#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging
from datetime import datetime
from datetime import timezone
from traceback import format_exc as traceback_format_exc
from typing import Iterable

from aboutcode.pipeline import BasePipeline
from aboutcode.pipeline import LoopProgress

from vulnerabilities import import_runner
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.improvers.default import DefaultImporter
from vulnerabilities.models import Advisory
from vulnerabilities.utils import classproperty

module_logger = logging.getLogger(__name__)


class VulnerableCodePipeline(BasePipeline):
    def log(self, message, level=logging.INFO):
        """Log the given `message` to the current module logger and execution_log."""
        now_local = datetime.now(timezone.utc).astimezone()
        timestamp = now_local.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        message = f"{timestamp} {message}"
        module_logger.log(level, message)
        self.append_to_log(message)

    @classproperty
    def qualified_name(cls):
        """
        Fully qualified name prefixed with the module name of the pipeline used in logging.
        """
        return f"{cls.__module__}.{cls.__qualname__}"


class VulnerableCodeBaseImporterPipeline(VulnerableCodePipeline):
    """
    Base importer pipeline for importing advisories.

    Uses:
        Subclass this Pipeline and implement ``advisories_count`` and ``collect_advisories`` method.
        Also override the ``steps`` if needed.
    """

    license_url = None
    spdx_license_expression = None
    repo_url = None
    importer_name = None

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
        self.new_advisories = []

        collected_advisory_count = 0
        progress = LoopProgress(total_iterations=self.advisories_count(), logger=self.log)
        for advisory in progress.iter(self.collect_advisories()):
            self.insert_advisory(advisory=advisory)
            collected_advisory_count += 1

        self.log(f"Successfully collected {collected_advisory_count:,d} advisories")

    def insert_advisory(self, advisory: AdvisoryData):
        try:
            obj, created = Advisory.objects.get_or_create(
                aliases=advisory.aliases,
                summary=advisory.summary,
                affected_packages=[pkg.to_dict() for pkg in advisory.affected_packages],
                references=[ref.to_dict() for ref in advisory.references],
                date_published=advisory.date_published,
                weaknesses=advisory.weaknesses,
                defaults={
                    "created_by": self.qualified_name,
                    "date_collected": datetime.now(timezone.utc),
                },
                url=advisory.url,
            )
            if created:
                self.new_advisories.append(obj)
        except Exception as e:
            self.log(
                f"Error while processing {advisory!r} with aliases {advisory.aliases!r}: {e!r} \n {traceback_format_exc()}",
                level=logging.ERROR,
            )

    def import_new_advisories(self):
        new_advisories_count = len(self.new_advisories)

        imported_advisory_count = 0
        progress = LoopProgress(total_iterations=new_advisories_count, logger=self.log)
        for advisory in progress.iter(self.new_advisories):
            self.import_advisory(advisory=advisory)
            imported_advisory_count += 1

        self.log(f"Successfully imported {imported_advisory_count:,d} new advisories")

    def import_advisory(self, advisory) -> None:
        if advisory.date_imported:
            return
        try:
            advisory_importer = DefaultImporter(advisories=[advisory])
            inferences = advisory_importer.get_inferences(advisory_data=advisory.to_advisory_data())
            import_runner.process_inferences(
                inferences=inferences,
                advisory=advisory,
                improver_name=self.qualified_name,
            )
        except Exception as e:
            self.log(
                f"Failed to process advisory: {advisory!r} with error {e!r}", level=logging.ERROR
            )
