#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import re
import traceback
from abc import abstractmethod
from collections import defaultdict
from datetime import datetime
from datetime import timezone
from timeit import default_timer as timer
from traceback import format_exc as traceback_format_exc
from typing import Iterable
from typing import List
from urllib.parse import urlparse

import gitlab
from aboutcode.pipeline import LoopProgress
from aboutcode.pipeline import PipelineDefinition
from aboutcode.pipeline import humanize_time
from github import Github

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.models import Advisory
from vulnerabilities.models import PipelineRun
from vulnerabilities.pipes.advisory import import_advisory
from vulnerabilities.pipes.advisory import insert_advisory
from vulnerabilities.pipes.advisory import insert_advisory_v2
from vulnerablecode.settings import env

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
        **kwargs,
    ):
        """Load the Pipeline class."""
        self.run = run_instance
        self.pipeline_class = self.__class__
        self.pipeline_name = self.__class__.__name__

        self.selected_groups = selected_groups
        self.selected_steps = selected_steps or []

        self.execution_log = []
        self.current_step = ""

        # Optional args used as input in downstream pipeline steps
        self.inputs = kwargs

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

    # When set to true pipeline is run only once.
    # To rerun onetime pipeline reset is_active field to True via migration.
    run_once = False

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
    ignorable_versions = []

    # When set to true pipeline is run only once.
    # To rerun onetime pipeline reset is_active field to True via migration.
    run_once = False

    @classmethod
    def steps(cls):
        return (
            # Add step for downloading/cloning resource as required.
            cls.collect_and_store_advisories,
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
            if advisory is None:
                self.log("Advisory is None, skipping")
                continue
            try:
                if _obj := insert_advisory_v2(
                    advisory=advisory,
                    pipeline_id=self.pipeline_id,
                    logger=self.log,
                ):
                    collected_advisory_count += 1
            except Exception as e:
                self.log(
                    f"Failed to import advisory: {advisory!r} with error {e!r}:\n{traceback_format_exc()}",
                    level=logging.ERROR,
                )
                continue

        self.log(f"Successfully collected {collected_advisory_count:,d} advisories")


class VCSCollector(VulnerableCodeBaseImporterPipeline):
    """
    Pipeline to collect GitHub/GitLab issues and PRs related to vulnerabilities.
    """

    vcs_url: str
    CVE_PATTERN = re.compile(r"(CVE-\d{4}-\d+)", re.IGNORECASE)
    SUPPORTED_IDENTIFIERS = ["CVE-"]

    collected_items: dict = {}

    def advisories_count(self) -> int:
        return 0

    @classmethod
    def steps(cls):
        return (
            cls.configure_target,
            cls.fetch_entries,
            cls.collect_items,
            cls.collect_and_store_advisories,
        )

    def configure_target(self):
        parsed_url = urlparse(self.repo_url)
        parts = parsed_url.path.strip("/").split("/")
        if len(parts) < 2:
            raise ValueError(f"Invalid URL: {self.repo_url}")

        self.repo_name = f"{parts[0]}/{parts[1]}"

    @abstractmethod
    def fetch_entries(self):
        raise NotImplementedError

    @abstractmethod
    def collect_items(self):
        raise NotImplementedError

    def collect_advisories(self):
        """
        Generate AdvisoryData objects for each vulnerability ID grouped with its related GitHub/Gitlab issues and PRs.
        """
        self.log("Generating AdvisoryData objects from GitHub/Gitlab issues and PRs.")
        for vuln_id, refs in self.collected_items.items():
            print(vuln_id, refs)
            references = [ReferenceV2(reference_type=ref_id, url=url) for ref_id, url in refs]
            yield AdvisoryData(
                advisory_id=vuln_id,
                aliases=[],
                references_v2=references,
                url=self.repo_url,
            )


class GitHubCollector(VCSCollector):
    def fetch_entries(self):
        """Fetch GitHub Data Entries"""
        github_token = env.str("GITHUB_TOKEN")
        g = Github(login_or_token=github_token)
        base_query = f"repo:{self.repo_name} ({' OR '.join(self.SUPPORTED_IDENTIFIERS)})"
        self.issues = g.search_issues(f"{base_query} is:issue")
        self.prs = g.search_issues(f"{base_query} is:pr")

    def collect_items(self):
        self.collected_items = defaultdict(list)

        for i_type, items in [("Issue", self.issues), ("PR", self.prs)]:
            for item in items:
                matches = self.CVE_PATTERN.findall(item.title + " " + (item.body or ""))
                for match in matches:
                    self.collected_items[match].append(("Issue", item.html_url))


class GitLabCollector(VCSCollector):
    def fetch_entries(self):
        """Fetch GitLab Data Entries"""
        gitlab_token = env.str("GITLAB_TOKEN")
        gl = gitlab.Gitlab("https://gitlab.com/", private_token=gitlab_token)
        project = gl.projects.get(self.repo_name)
        base_query = " ".join(self.SUPPORTED_IDENTIFIERS)
        self.issues = project.search(scope="issues", search=base_query)
        self.prs = project.search(scope="merge_requests", search=base_query)

    def collect_items(self):
        self.collected_items = defaultdict(list)
        for i_type, items in [("Issue", self.issues), ("PR", self.prs)]:
            for item in items:
                title = item.get("title") or ""
                description = item.get("description") or ""
                matches = self.CVE_PATTERN.findall(title + " " + description)
                for match in matches:
                    url = item.get("web_url")
                    self.collected_items[match].append((i_type, url))
