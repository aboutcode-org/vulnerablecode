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

from aboutcode.federated import DataFederation
from vulnerabilities.models import PackageV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes import federatedcode


class FederatePackageVulnerabilities(VulnerableCodePipeline):
    """Export package vulnerabilities and advisory to FederatedCode."""

    pipeline_id = "federate_package_vulnerabilities_v2"

    @classmethod
    def steps(cls):
        return (
            cls.check_federatedcode_eligibility,
            cls.create_federatedcode_working_dir,
            cls.fetch_federation_config,
            cls.clone_vulnerabilities_repo,
            cls.publish_vulnerabilities,
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

    def publish_vulnerabilities(self):
        """Publish package vulnerabilities and advisory to FederatedCode"""
        repo_path = Path(self.repo.working_dir)
        commit_count = 1
        batch_size = 2000
        files_to_commit = set()
        exported_avids = set()

        distinct_packages_count = (
            PackageV2.objects.values("type", "namespace", "name")
            .distinct("type", "namespace", "name")
            .count()
        )
        package_qs = package_prefetched_qs()
        grouped_packages = itertools.groupby(
            package_qs.iterator(chunk_size=2000),
            key=attrgetter("type", "namespace", "name"),
        )

        self.log(f"Exporting vulnerabilities for {distinct_packages_count} packages.")
        progress = LoopProgress(
            total_iterations=distinct_packages_count,
            progress_step=1,
            logger=self.log,
        )
        for _, packages in progress.iter(grouped_packages):
            package_urls = []
            package_vulnerabilities = []
            for package in packages:
                purl = package.package_url
                package_urls.append(purl)
                package_vulnerabilities.append(serialize_package_vulnerability(package))

                impacts = itertools.chain(
                    package.affected_in_impacts.all(),
                    package.fixed_in_impacts.all(),
                )
                for impact in impacts:
                    adv = impact.advisory
                    avid = adv.avid
                    if avid in exported_avids:
                        continue

                    exported_avids.add(avid)
                    advisory = serialize_advisory(adv)
                    adv_file = f"vulnerabilities/{avid}.yml"
                    write_file(
                        repo_path=repo_path,
                        file_path=adv_file,
                        data=advisory,
                    )
                    files_to_commit.add(adv_file)

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
                    commit_message=self.commit_message(commit_count),
                    repo=self.repo,
                    files_to_commit=files_to_commit,
                    logger=self.log,
                ):
                    commit_count += 1
                files_to_commit.clear()

        if files_to_commit:
            federatedcode.commit_and_push_changes(
                commit_message=self.commit_message(commit_count, commit_count),
                repo=self.repo,
                files_to_commit=files_to_commit,
                logger=self.log,
            )

        self.log(
            f"Federated {distinct_packages_count} package and {len(exported_avids)} vulnerabilities."
        )

    def delete_working_dir(self):
        """Remove temporary working dir."""
        if hasattr(self, "working_path") and self.working_path:
            shutil.rmtree(self.working_path)

    def on_failure(self):
        self.delete_working_dir()

    def commit_message(self, commit_count, total_commit_count="many"):
        """Commit message for pushing Package vulnerability."""
        return federatedcode.commit_message(
            commit_count=commit_count,
            total_commit_count=total_commit_count,
        )


def package_prefetched_qs():
    return PackageV2.objects.order_by("type", "namespace", "name", "version").prefetch_related(
        "affected_in_impacts",
        "affected_in_impacts__advisory",
        "affected_in_impacts__advisory__impacted_packages",
        "affected_in_impacts__advisory__aliases",
        "affected_in_impacts__advisory__references",
        "affected_in_impacts__advisory__severities",
        "affected_in_impacts__advisory__weaknesses",
        "fixed_in_impacts",
        "fixed_in_impacts__advisory",
        "fixed_in_impacts__advisory__impacted_packages",
        "fixed_in_impacts__advisory__aliases",
        "fixed_in_impacts__advisory__references",
        "fixed_in_impacts__advisory__severities",
        "fixed_in_impacts__advisory__weaknesses",
    )


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
