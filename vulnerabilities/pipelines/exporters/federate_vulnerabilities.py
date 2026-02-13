# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import itertools
import shutil
from operator import attrgetter
from pathlib import Path

import saneyaml
from aboutcode.pipeline import LoopProgress
from django.conf import settings
from django.db.models import Prefetch

from aboutcode.federated import DataFederation
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes import federatedcode


class FederatePackageVulnerabilities(VulnerableCodePipeline):
    """Export package vulnerabilities and advisory to FederatedCode."""

    pipeline_id = "federate_vulnerabilities_v2"

    @classmethod
    def steps(cls):
        return (
            cls.check_federatedcode_eligibility,
            cls.create_federatedcode_working_dir,
            cls.fetch_federation_config,
            cls.clone_vulnerabilities_repo,
            cls.publish_package_vulnerabilities,
            cls.publish_advisories,
            cls.delete_working_dir,
        )

    def check_federatedcode_eligibility(self):
        """Check if FederatedCode is configured."""
        federatedcode.check_federatedcode_configured_and_available(self.log)

    def create_federatedcode_working_dir(self):
        """Create temporary working dir."""
        self.working_path = federatedcode.create_federatedcode_working_dir()

    def fetch_federation_config(self):
        """Fetch config for PackageURL Federation."""
        data_federation = DataFederation.from_url(
            name="aboutcode-data",
            remote_root_url="https://github.com/aboutcode-data",
        )
        self.data_cluster = data_federation.get_cluster("purls")

    def clone_vulnerabilities_repo(self):
        self.repo = federatedcode.clone_repository(
            repo_url=settings.FEDERATEDCODE_VULNERABILITIES_REPO,
            clone_path=self.working_path / "vulnerabilities-data",
            logger=self.log,
        )

    def publish_package_vulnerabilities(self):
        """Publish package vulnerabilities to FederatedCode"""
        repo_path = Path(self.repo.working_dir)
        commit_count = 1
        batch_size = 2000
        chunk_size = 1000
        files_to_commit = set()

        distinct_packages_count = (
            PackageV2.objects.values("type", "namespace", "name")
            .distinct("type", "namespace", "name")
            .count()
        )
        package_qs = package_prefetched_qs()
        grouped_packages = itertools.groupby(
            package_qs.iterator(chunk_size=chunk_size),
            key=attrgetter("type", "namespace", "name"),
        )

        self.log(f"Exporting vulnerabilities for {distinct_packages_count} packages.")
        progress = LoopProgress(
            total_iterations=distinct_packages_count,
            progress_step=5,
            logger=self.log,
        )
        for _, packages in progress.iter(grouped_packages):
            package_urls, package_vulnerabilities = get_package_vulnerabilities(packages)
            purl = package_urls[0]
            package_repo, datafile_path = self.data_cluster.get_datafile_repo_and_path(purl=purl)
            package_vulnerability_path = datafile_path.replace("/purls.yml", "/vulnerabilities.yml")
            package_vulnerability_path = f"packages/{package_repo}/{package_vulnerability_path}"
            package_path = f"packages/{package_repo}/{datafile_path}"

            write_file(
                repo_path=repo_path,
                file_path=package_path,
                data=package_urls,
            )
            files_to_commit.add(package_path)

            write_file(
                repo_path=repo_path,
                file_path=package_vulnerability_path,
                data=package_vulnerabilities,
            )
            files_to_commit.add(package_vulnerability_path)

            if len(files_to_commit) > batch_size:
                if federatedcode.commit_and_push_changes(
                    commit_message=self.commit_message("package vulnerabilities", commit_count),
                    repo=self.repo,
                    files_to_commit=files_to_commit,
                    logger=self.log,
                ):
                    commit_count += 1
                files_to_commit.clear()

        if files_to_commit:
            federatedcode.commit_and_push_changes(
                commit_message=self.commit_message(
                    "package vulnerabilities",
                    commit_count,
                    commit_count,
                ),
                repo=self.repo,
                files_to_commit=files_to_commit,
                logger=self.log,
            )

        self.log(f"Federated {distinct_packages_count} package vulnerabilities.")

    def publish_advisories(self):
        """Publish advisory to FederatedCode"""
        repo_path = Path(self.repo.working_dir)
        commit_count = 1
        batch_size = 2000
        chunk_size = 1000
        files_to_commit = set()
        advisory_qs = advisory_prefetched_qs()
        advisory_count = advisory_qs.count()

        self.log(f"Exporting vulnerabilities for {advisory_count} advisory.")
        progress = LoopProgress(
            total_iterations=advisory_count,
            progress_step=5,
            logger=self.log,
        )
        for advisory in progress.iter(advisory_qs.iterator(chunk_size=chunk_size)):
            advisory_data = serialize_advisory(advisory)
            adv_file = f"vulnerabilities/{advisory.avid}.yml"
            write_file(
                repo_path=repo_path,
                file_path=adv_file,
                data=advisory_data,
            )
            files_to_commit.add(adv_file)

            if len(files_to_commit) > batch_size:
                if federatedcode.commit_and_push_changes(
                    commit_message=self.commit_message("advisories", commit_count),
                    repo=self.repo,
                    files_to_commit=files_to_commit,
                    logger=self.log,
                ):
                    commit_count += 1
                files_to_commit.clear()

        if files_to_commit:
            federatedcode.commit_and_push_changes(
                commit_message=self.commit_message(
                    "advisories",
                    commit_count,
                    commit_count,
                ),
                repo=self.repo,
                files_to_commit=files_to_commit,
                logger=self.log,
            )

        self.log(f"Successfully federated {advisory_count} vulnerabilities.")

    def delete_working_dir(self):
        """Remove temporary working dir."""
        if hasattr(self, "working_path") and self.working_path:
            shutil.rmtree(self.working_path)

    def on_failure(self):
        self.delete_working_dir()

    def commit_message(
        self,
        item_type,
        commit_count,
        total_commit_count="many",
    ):
        """Commit message for pushing Package vulnerability."""
        return federatedcode.commit_message(
            item_type=item_type,
            commit_count=commit_count,
            total_commit_count=total_commit_count,
        )


def package_prefetched_qs():
    return (
        PackageV2.objects.order_by("type", "namespace", "name", "version")
        .only("id", "package_url", "type", "namespace", "name", "version")
        .prefetch_related(
            Prefetch(
                "affected_in_impacts",
                queryset=ImpactedPackage.objects.only("id", "advisory_id").prefetch_related(
                    Prefetch(
                        "advisory",
                        queryset=AdvisoryV2.objects.only("id", "avid"),
                    )
                ),
            ),
            Prefetch(
                "fixed_in_impacts",
                queryset=ImpactedPackage.objects.only("id", "advisory_id").prefetch_related(
                    Prefetch(
                        "advisory",
                        queryset=AdvisoryV2.objects.only("id", "avid"),
                    )
                ),
            ),
        )
    )


def advisory_prefetched_qs():
    return AdvisoryV2.objects.prefetch_related(
        "impacted_packages",
        "aliases",
        "references",
        "severities",
        "weaknesses",
    )


def get_package_vulnerabilities(packages):
    """Return list of PURLs and serialized package vulnerability"""
    package_urls = []
    package_vulnerabilities = []
    for package in packages:
        package_urls.append(package.package_url)
        package_vulnerabilities.append(serialize_package_vulnerability(package))
    return package_urls, package_vulnerabilities


def serialize_package_vulnerability(package):
    affected_by_vulnerabilities = [
        impact.advisory.avid for impact in package.affected_in_impacts.all()
    ]
    fixing_vulnerabilities = [impact.advisory.avid for impact in package.fixed_in_impacts.all()]

    return {
        "purl": package.package_url,
        "affected_by_vulnerabilities": affected_by_vulnerabilities,
        "fixing_vulnerabilities": fixing_vulnerabilities,
    }


def serialize_severity(sev):
    return {
        "score": sev.value,
        "scoring_system": sev.scoring_system,
        "scoring_elements": sev.scoring_elements,
        "published_at": str(sev.published_at),
        "url": sev.url,
    }


def serialize_references(reference):
    return {
        "url": reference.url,
        "reference_type": reference.reference_type,
        "reference_id": reference.reference_id,
    }


def serialize_advisory(advisory):
    """Return a plain data mapping serialized from advisory object."""
    aliases = [a.alias for a in advisory.aliases.all()]
    severities = [serialize_severity(sev) for sev in advisory.severities.all()]
    weaknesses = [wkns.cwe for wkns in advisory.weaknesses.all()]
    references = [serialize_references(ref) for ref in advisory.references.all()]
    impacts = [
        {
            "purl": impact.base_purl,
            "affected_versions": impact.affecting_vers,
            "fixed_versions": impact.fixed_vers,
        }
        for impact in advisory.impacted_packages.all()
    ]

    return {
        "advisory_id": advisory.advisory_id,
        "datasource_id": advisory.avid,
        "datasource_url": advisory.url,
        "aliases": aliases,
        "summary": advisory.summary,
        "impacted_packages": impacts,
        "severities": severities,
        "weaknesses": weaknesses,
        "references": references,
    }


def write_file(repo_path, file_path, data):
    """Write ``data`` as YAML to ``repo_path``."""
    write_to = repo_path / file_path
    write_to.parent.mkdir(parents=True, exist_ok=True)
    with open(write_to, encoding="utf-8", mode="w") as f:
        f.write(saneyaml.dump(data))
