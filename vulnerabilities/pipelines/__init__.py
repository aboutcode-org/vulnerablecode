#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import traceback
from datetime import datetime
from datetime import timezone
from timeit import default_timer as timer
from traceback import format_exc as traceback_format_exc
from typing import Iterable
from typing import List
from typing import Optional

from aboutcode.pipeline import LoopProgress
from aboutcode.pipeline import PipelineDefinition
from aboutcode.pipeline import humanize_time
from fetchcode import package_versions
from packageurl import PackageURL

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import UnMergeablePackageError
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.models import Advisory
from vulnerabilities.models import PackageV2
from vulnerabilities.models import PipelineRun
from vulnerabilities.pipes.advisory import import_advisory
from vulnerabilities.pipes.advisory import insert_advisory
from vulnerabilities.pipes.advisory import insert_advisory_v2
from vulnerabilities.utils import AffectedPackage as LegacyAffectedPackage
from vulnerabilities.utils import classproperty
from vulnerabilities.utils import get_affected_packages_by_patched_package
from vulnerabilities.utils import nearest_patched_package
from vulnerabilities.utils import resolve_version_range

module_logger = logging.getLogger(__name__)


class BasePipelineRun:
    """
    Encapsulate the code related to a Pipeline run (execution):
    - Execution context: groups, steps
    - Execution logic
    - Logging
    - Results
    """

    def __init__(
        self,
        run_instance: PipelineRun = None,
        selected_groups: List = None,
        selected_steps: List = None,
    ):
        """Load the Pipeline class."""
        self.run = run_instance
        self.pipeline_class = self.__class__
        self.pipeline_name = self.__class__.__name__

        self.selected_groups = selected_groups
        self.selected_steps = selected_steps or []

        self.execution_log = []
        self.current_step = ""

    def append_to_log(self, message):
        if self.run and self.run.pipeline.live_logging:
            self.run.append_to_log(message)
        self.execution_log.append(message)

    def update_final_run_log(self):
        if self.run and not self.run.pipeline.live_logging:
            final_log = "\n".join(self.execution_log)
            self.run.append_to_log(final_log, is_multiline=True)

    def set_current_step(self, message):
        self.current_step = message

    @staticmethod
    def output_from_exception(exception):
        """Return a formatted error message including the traceback."""
        output = f"{exception}\n\n"

        if exception.__cause__ and str(exception.__cause__) != str(exception):
            output += f"Cause: {exception.__cause__}\n\n"

        traceback_formatted = "".join(traceback.format_tb(exception.__traceback__))
        output += f"Traceback:\n{traceback_formatted}"

        return output

    def execute(self):
        """Execute each steps in the order defined on this pipeline class."""
        self.log(f"Pipeline [{self.pipeline_name}] starting")

        steps = self.pipeline_class.get_steps(groups=self.selected_groups)
        steps_count = len(steps)
        pipeline_start_time = timer()

        for current_index, step in enumerate(steps, start=1):
            step_name = step.__name__

            if self.selected_steps and step_name not in self.selected_steps:
                self.log(f"Step [{step_name}] skipped")
                continue

            self.set_current_step(f"{current_index}/{steps_count} {step_name}")
            self.log(f"Step [{step_name}] starting")
            step_start_time = timer()

            try:
                step(self)
            except Exception as exception:
                self.log("Pipeline failed")
                on_failure_start_time = timer()
                self.log(f"Running [on_failure] tasks")
                self.on_failure()
                on_failure_run_time = timer() - on_failure_start_time
                self.log(f"Completed [on_failure] tasks in {humanize_time(on_failure_run_time)}")
                self.update_final_run_log()

                return 1, self.output_from_exception(exception)

            step_run_time = timer() - step_start_time
            self.log(f"Step [{step_name}] completed in {humanize_time(step_run_time)}")

        self.set_current_step("")  # Reset the `current_step` field on completion
        pipeline_run_time = timer() - pipeline_start_time
        self.log(f"Pipeline completed in {humanize_time(pipeline_run_time)}")
        self.update_final_run_log()

        return 0, ""

    def log(self, message, level=logging.INFO):
        """Log the given `message` to the current module logger and execution_log."""
        now_local = datetime.now(timezone.utc).astimezone()
        timestamp = now_local.strftime("%Y-%m-%d %T.%f %Z")
        message = f"{timestamp} {message}"
        module_logger.log(level, message)
        self.append_to_log(message)


class VulnerableCodePipeline(PipelineDefinition, BasePipelineRun):
    pipeline_id = None  # Unique Pipeline ID

    def on_failure(self):
        """
        Tasks to run in the event that pipeline execution fails.

        Implement cleanup or other tasks that need to be performed
        on pipeline failure, such as:
            - Removing cloned repositories.
            - Deleting downloaded archives.
        """
        pass


class VulnerableCodeBaseImporterPipeline(VulnerableCodePipeline):
    """
    Base importer pipeline for importing advisories.

    Uses:
        Subclass this Pipeline and implement ``advisories_count`` and ``collect_advisories``
        method. Also override the ``steps`` and ``advisory_confidence`` as needed.
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
            if isinstance(advisory, AdvisoryData):
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


class VulnerableCodeBaseImporterPipelineV2(VulnerableCodePipeline):
    """
    Base importer pipeline for importing advisories.

    Uses:
        Subclass this Pipeline and implement ``advisories_count`` and ``collect_advisories``
        method. Also override the ``steps`` and ``advisory_confidence`` as needed.
    """

    pipeline_id = None  # Unique Pipeline ID, this should be the name of pipeline module.
    license_url = None
    spdx_license_expression = None
    repo_url = None
    advisory_confidence = MAX_CONFIDENCE
    ignorable_versions = []
    unfurl_version_ranges = False

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_advisories,)

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
            if advisory is None:
                self.log("Advisory is None, skipping")
                continue
            if _obj := insert_advisory_v2(
                advisory=advisory,
                pipeline_id=self.pipeline_id,
                get_advisory_packages=self.get_advisory_packages,
                logger=self.log,
            ):
                collected_advisory_count += 1

        self.log(f"Successfully collected {collected_advisory_count:,d} advisories")

    def get_advisory_packages(self, advisory_data: AdvisoryData) -> list:
        """
        Return the list of packages for the given advisory.

        Used by ``import_advisory`` to get the list of packages for the advisory.
        """
        from vulnerabilities.improvers import default

        affected_purls = []
        fixed_purls = []
        for affected_package in advisory_data.affected_packages:
            package_affected_purls, package_fixed_purls = default.get_exact_purls(
                affected_package=affected_package
            )
            affected_purls.extend(package_affected_purls)
            fixed_purls.extend(package_fixed_purls)

        if self.unfurl_version_ranges:
            vulnerable_pvs, fixed_pvs = self.get_impacted_packages(
                affected_packages=advisory_data.affected_packages,
                advisory_date_published=advisory_data.date_published,
            )
            affected_purls.extend(vulnerable_pvs)
            fixed_purls.extend(fixed_pvs)

        vulnerable_packages = []
        fixed_packages = []

        for affected_purl in affected_purls:
            vulnerable_package, _ = PackageV2.objects.get_or_create_from_purl(purl=affected_purl)
            vulnerable_packages.append(vulnerable_package)

        for fixed_purl in fixed_purls:
            fixed_package, _ = PackageV2.objects.get_or_create_from_purl(purl=fixed_purl)
            fixed_packages.append(fixed_package)

        return vulnerable_packages, fixed_packages

    def get_published_package_versions(
        self, package_url: PackageURL, until: Optional[datetime] = None
    ) -> List[str]:
        """
        Return a list of versions published before `until` for the `package_url`
        """
        versions_before_until = []
        try:
            versions = package_versions.versions(str(package_url))
            for version in versions or []:
                if until and version.release_date and version.release_date > until:
                    continue
                versions_before_until.append(version.value)

            return versions_before_until
        except Exception as e:
            self.log(
                f"Failed to fetch versions for package {str(package_url)} {e!r}",
                level=logging.ERROR,
            )
            return []

    def get_impacted_packages(self, affected_packages, advisory_date_published):
        """
        Return a tuple of lists of affected and fixed PackageURLs
        """
        if not affected_packages:
            return [], []

        mergable = True

        # TODO: We should never had the exception in first place
        try:
            purl, affected_version_ranges, fixed_versions = AffectedPackage.merge(affected_packages)
        except UnMergeablePackageError:
            self.log(f"Cannot merge with different purls {affected_packages!r}", logging.ERROR)
            mergable = False

        if not mergable:
            vulnerable_packages = []
            fixed_packages = []
            for affected_package in affected_packages:
                purl = affected_package.package
                affected_version_range = affected_package.affected_version_range
                fixed_version = affected_package.fixed_version
                pkg_type = purl.type
                pkg_namespace = purl.namespace
                pkg_name = purl.name
                if not affected_version_range and fixed_version:
                    fixed_packages.append(
                        PackageURL(
                            type=pkg_type,
                            namespace=pkg_namespace,
                            name=pkg_name,
                            version=str(fixed_version),
                        )
                    )
                else:
                    valid_versions = self.get_published_package_versions(
                        package_url=purl, until=advisory_date_published
                    )
                    affected_pvs, fixed_pvs = self.resolve_package_versions(
                        affected_version_range=affected_version_range,
                        pkg_type=pkg_type,
                        pkg_namespace=pkg_namespace,
                        pkg_name=pkg_name,
                        valid_versions=valid_versions,
                    )
                    vulnerable_packages.extend(affected_pvs)
                    fixed_packages.extend(fixed_pvs)
            return vulnerable_packages, fixed_packages
        else:
            pkg_type = purl.type
            pkg_namespace = purl.namespace
            pkg_name = purl.name
            pkg_qualifiers = purl.qualifiers
            fixed_purls = [
                PackageURL(
                    type=pkg_type,
                    namespace=pkg_namespace,
                    name=pkg_name,
                    version=str(version),
                    qualifiers=pkg_qualifiers,
                )
                for version in fixed_versions
            ]
            if not affected_version_ranges:
                return [], fixed_purls
            else:
                valid_versions = self.get_published_package_versions(
                    package_url=purl, until=advisory_date_published
                )
                vulnerable_packages = []
                fixed_packages = []
                for affected_version_range in affected_version_ranges:
                    vulnerable_pvs, fixed_pvs = self.resolve_package_versions(
                        affected_version_range=affected_version_range,
                        pkg_type=pkg_type,
                        pkg_namespace=pkg_namespace,
                        pkg_name=pkg_name,
                        valid_versions=valid_versions,
                    )
                    vulnerable_packages.extend(vulnerable_pvs)
                    fixed_packages.extend(fixed_pvs)
                return vulnerable_packages, fixed_packages

    def resolve_package_versions(
        self,
        affected_version_range,
        pkg_type,
        pkg_namespace,
        pkg_name,
        valid_versions,
    ):
        """
        Return a tuple of lists of ``affected_packages`` and ``fixed_packages`` PackageURL for the given `affected_version_range` and `valid_versions`.

        ``valid_versions`` are the valid version listed on the package registry for that package

        """
        aff_vers, unaff_vers = resolve_version_range(
            affected_version_range=affected_version_range,
            ignorable_versions=self.ignorable_versions,
            package_versions=valid_versions,
        )

        affected_purls = list(
            self.expand_verion_range_to_purls(pkg_type, pkg_namespace, pkg_name, aff_vers)
        )

        unaffected_purls = list(
            self.expand_verion_range_to_purls(pkg_type, pkg_namespace, pkg_name, unaff_vers)
        )

        fixed_packages = []
        affected_packages = []

        patched_packages = nearest_patched_package(
            vulnerable_packages=affected_purls, resolved_packages=unaffected_purls
        )

        for (
            fixed_package,
            affected_purls,
        ) in get_affected_packages_by_patched_package(patched_packages).items():
            if fixed_package:
                fixed_packages.append(fixed_package)
            affected_packages.extend(affected_purls)

        return affected_packages, fixed_packages

    def expand_verion_range_to_purls(self, pkg_type, pkg_namespace, pkg_name, versions):
        for version in versions:
            yield PackageURL(type=pkg_type, namespace=pkg_namespace, name=pkg_name, version=version)
