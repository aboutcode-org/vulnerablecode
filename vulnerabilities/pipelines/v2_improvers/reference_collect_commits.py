#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from aboutcode.pipeline import LoopProgress
from django.db.models import Prefetch
from packageurl.contrib.purl2url import purl2url
from packageurl.contrib.url2purl import url2purl

from aboutcode.federated import get_core_purl
from vulnerabilities.models import AdvisoryReference
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import ImpactedPackage
from vulnerabilities.models import PackageCommitPatch
from vulnerabilities.models import Patch
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import is_commit


class CollectReferencesFixCommitsPipeline(VulnerableCodePipeline):
    """
    Improver pipeline to scout References/Patch and create PackageCommitPatch entries.
    """

    pipeline_id = "collect_ref_fix_commits_v2"

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_fix_commits,)

    def get_vcs_data(self, url):
        """Extracts a VCS URL and commit hash from URL.
        >> get_vcs_commit('https://github.com/aboutcode-org/vulnerablecode/commit/98e516011d6e096e25247b82fc5f196bbeecff10')
        ("pkg:github/aboutcode-org/vulnerablecode", 'https://github.com/aboutcode-org/vulnerablecode', '98e516011d6e096e25247b82fc5f196bbeecff10')
        >> get_vcs_commit('https://github.com/aboutcode-org/vulnerablecode/pull/1974')
        None
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
            self.log(f"Invalid URL: url:{url} error:{e}")

    def collect_and_store_fix_commits(self):
        advisories = AdvisoryV2.objects.only("id").prefetch_related(
            Prefetch("references", queryset=AdvisoryReference.objects.only("url")),
            Prefetch("patches", queryset=Patch.objects.only("patch_url")),
        )

        progress = LoopProgress(total_iterations=advisories.count(), logger=self.log)

        commit_batch = []
        updated_pkg_patch_commit_count = 0
        batch_size = 1000
        for adv in progress.iter(advisories.paginated(per_page=batch_size)):
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

        self.log(f"Successfully processed pkg patch commit {updated_pkg_patch_commit_count:,d}")

    def bulk_commit_batch_update(self, vcs_data_table):
        impact_data = {(row[0], row[3]) for row in vcs_data_table}  # base_purl, adv_id
        commit_data = {(row[1], row[2]) for row in vcs_data_table}  # vcs_url, commit_hash

        adv_ids = {aid for _, aid in impact_data}
        existing_impacts = ImpactedPackage.objects.filter(advisory_id__in=adv_ids)
        existing_impact_pairs = {(ip.base_purl, ip.advisory_id) for ip in existing_impacts}

        new_impacts = impact_data - existing_impact_pairs
        if new_impacts:
            ImpactedPackage.objects.bulk_create(
                [ImpactedPackage(base_purl=bp, advisory_id=aid) for bp, aid in new_impacts]
            )

        PackageCommitPatch.objects.bulk_create(
            [
                PackageCommitPatch(vcs_url=vcs_url, commit_hash=commit_hash)
                for vcs_url, commit_hash in commit_data
            ],
            ignore_conflicts=True,
        )

        adv_ids = {adv_id for _, adv_id in impact_data}
        fetched_impacts = {
            (impacted_pkg.base_purl, impacted_pkg.advisory_id): impacted_pkg
            for impacted_pkg in ImpactedPackage.objects.filter(advisory_id__in=adv_ids)
        }

        commit_hashes = {commit_hash for _, commit_hash in commit_data}
        fetched_commits = {
            (pkg_commit_patch.vcs_url, pkg_commit_patch.commit_hash): pkg_commit_patch
            for pkg_commit_patch in PackageCommitPatch.objects.filter(commit_hash__in=commit_hashes)
        }

        for base_purl, vcs_url, commit_hash, adv_id in vcs_data_table:
            impacted_package = fetched_impacts.get((base_purl, adv_id))
            package_commit_obj = fetched_commits.get((vcs_url, commit_hash))

            if impacted_package and package_commit_obj:
                package_commit_obj.fixed_in_impacts.add(impacted_package)

        return len(vcs_data_table)
