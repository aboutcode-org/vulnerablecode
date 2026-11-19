#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from tempfile import TemporaryDirectory

from aboutcode.federated import get_core_purl
from aboutcode.pipeline import LoopProgress
from django.db.models import Prefetch
from git import Repo
from git.exc import GitError
from packageurl.contrib.purl2url import purl2url
from packageurl.contrib.url2purl import url2purl

from vulnerabilities.models import AdvisoryReference
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import PackageCommitPatch
from vulnerabilities.models import Patch
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.pipes.commit_reachability import get_branch_reachability
from vulnerabilities.utils import is_commit


class CollectReferencesFixCommitsPipeline(VulnerableCodePipeline):
    """
    Improver pipeline to scout References/Patch and create PackageCommitPatch entries.
    """

    pipeline_id = "collect_ref_fix_commits_v2"

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_fix_commits, cls.check_commit_branch_reachability)

    def check_commit_branch_reachability(self):
        """Check all collected commits, cloning each repository once per run.

        Collection remains independent of repository availability. A fresh, full
        bare clone includes all branch heads and their history, so even an object
        absent from that clone can be reported as unreachable from its branches.
        """
        vcs_urls = (
            PackageCommitPatch.objects.order_by("vcs_url")
            .values_list("vcs_url", flat=True)
            .distinct()
        )
        for vcs_url in vcs_urls.iterator():
            commits = list(
                PackageCommitPatch.objects.filter(vcs_url=vcs_url).only("id", "commit_hash")
            )
            results = dict.fromkeys(
                (commit.commit_hash for commit in commits),
                PackageCommitPatch.BranchReachability.UNKNOWN,
            )
            try:
                with TemporaryDirectory(prefix="vcio-commit-branches-") as directory:
                    with Repo.clone_from(
                        vcs_url,
                        directory,
                        bare=True,
                        single_branch=False,
                        no_local=True,
                        no_tags=True,
                        env={"GIT_TERMINAL_PROMPT": "0"},
                        kill_after_timeout=300,
                    ) as repo:
                        results = get_branch_reachability(repo, results, all_branches_fetched=True)
            except (GitError, OSError, ValueError) as error:
                self.log(f"Branch reachability unknown for {vcs_url}: {error}")

            for commit in commits:
                commit.branch_reachability = results[commit.commit_hash]
                if commit.branch_reachability == PackageCommitPatch.BranchReachability.UNREACHABLE:
                    self.log(
                        "Commit not reachable from repository branches: "
                        f"{vcs_url}@{commit.commit_hash}"
                    )

            PackageCommitPatch.objects.bulk_update(
                commits, fields=["branch_reachability"], batch_size=10000
            )

    def get_vcs_data(self, url):
        """Extract a core purl, VCS URL, and commit hash from a commit URL.

        Return None for non-commit URLs, including pull requests.
        """
        try:
            purl = url2purl(url)
            if not purl:
                return

            version = purl.version
            if not version or not is_commit(version):
                return
            base_purl = get_core_purl(purl)
            vcs_url = purl2url(base_purl.to_string())
            if base_purl and vcs_url and version:
                return base_purl, vcs_url, version
        except Exception as e:
            self.log(f"Invalid URL: url: {url} error: {e}")

    def collect_and_store_fix_commits(self):
        advisories = AdvisoryV2.objects.only("id").prefetch_related(
            Prefetch("references", queryset=AdvisoryReference.objects.only("id", "url")),
            Prefetch("patches", queryset=Patch.objects.only("id", "patch_url")),
        )

        progress = LoopProgress(total_iterations=advisories.count(), logger=self.log)

        commit_batch = []
        updated_pkg_patch_commit_count = 0
        batch_size = 10000
        for adv in progress.iter(advisories.iterator(chunk_size=batch_size)):
            urls = {r.url for r in adv.references.all()} | {p.patch_url for p in adv.patches.all()}

            for url in urls:
                vcs_data = self.get_vcs_data(url)
                if not vcs_data:
                    continue
                base_purl, vcs_url, commit_hash = vcs_data
                commit_batch.append((str(base_purl), vcs_url, commit_hash, adv.id))

            if len(commit_batch) >= batch_size:
                updated_pkg_patch_commit_count += self.bulk_commit_batch_update(commit_batch)
                commit_batch.clear()

        if commit_batch:
            updated_pkg_patch_commit_count += self.bulk_commit_batch_update(commit_batch)
            commit_batch.clear()

        processed_count = format(updated_pkg_patch_commit_count, ",d")
        self.log(f"Successfully processed pkg patch commit {processed_count}")

    def bulk_commit_batch_update(self, vcs_data_table):
        impact_data = {(row[0], row[3]) for row in vcs_data_table}  # base_purl, adv_id
        commit_data = {(row[1], row[2]) for row in vcs_data_table}  # vcs_url, commit_hash

        adv_ids = {adv_id for _, adv_id in impact_data}
        commit_hashes = {commit_hash for _, commit_hash in commit_data}

        existing_impacts = ImpactedPackage.objects.filter(advisory_id__in=adv_ids).only(
            "id", "base_purl", "advisory_id"
        )
        existing_impact_pairs = {
            (impact_pkg.base_purl, impact_pkg.advisory_id) for impact_pkg in existing_impacts
        }

        if new_impacts := impact_data - existing_impact_pairs:
            ImpactedPackage.objects.bulk_create(
                [
                    ImpactedPackage(base_purl=base_purl, advisory_id=adv_id)
                    for base_purl, adv_id in new_impacts
                ],
                ignore_conflicts=True,
            )

        PackageCommitPatch.objects.bulk_create(
            [
                PackageCommitPatch(vcs_url=vcs_url, commit_hash=commit_hash)
                for vcs_url, commit_hash in commit_data
            ],
            ignore_conflicts=True,
        )

        fetched_impacts = {
            (impacted_pkg.base_purl, impacted_pkg.advisory_id): impacted_pkg
            for impacted_pkg in ImpactedPackage.objects.filter(advisory_id__in=adv_ids).only(
                "id", "base_purl", "advisory_id"
            )
        }

        fetched_pkg_commits = {
            (pkg_commit_patch.vcs_url, pkg_commit_patch.commit_hash): pkg_commit_patch
            for pkg_commit_patch in PackageCommitPatch.objects.filter(
                commit_hash__in=commit_hashes
            ).only("id", "vcs_url", "commit_hash")
        }

        through_model = PackageCommitPatch.fixed_in_impacts.through

        relations = []
        for base_purl, vcs_url, commit_hash, adv_id in vcs_data_table:
            impacted_pkg_obj = fetched_impacts.get((base_purl, adv_id))
            pkg_commit_obj = fetched_pkg_commits.get((vcs_url, commit_hash))

            if impacted_pkg_obj and pkg_commit_obj:
                relations.append(
                    through_model(
                        packagecommitpatch_id=pkg_commit_obj.id,
                        impactedpackage_id=impacted_pkg_obj.id,
                    )
                )

        through_model.objects.bulk_create(
            relations,
            ignore_conflicts=True,
            batch_size=10000,
        )
        return len(vcs_data_table)
