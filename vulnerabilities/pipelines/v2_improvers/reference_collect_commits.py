#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from aboutcode.pipeline import LoopProgress
from packageurl.contrib.purl2url import purl2url
from packageurl.contrib.url2purl import url2purl

from aboutcode.federated import get_core_purl
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import PackageCommitPatch
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.advisory import VCS_URLS_SUPPORTED_TYPES
from vulnerabilities.utils import is_commit


class CollectReferencesFixCommitsPipeline(VulnerableCodeBaseImporterPipelineV2):
    """
    Improver pipeline to scout References/Patch and create PackageCommitPatch entries.
    """

    pipeline_id = "collect_ref_fix_commits_v2"

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_fix_commits,)

    def get_vcs_commit(self, url):
        """Extracts and VCS URL and commit hash from URL.
        >> get_vcs_commit('https://github.com/aboutcode-org/vulnerablecode/commit/98e516011d6e096e25247b82fc5f196bbeecff10')
        ('https://github.com/aboutcode-org/vulnerablecode', '98e516011d6e096e25247b82fc5f196bbeecff10')
        >> get_vcs_commit('https://github.com/aboutcode-org/vulnerablecode/pull/1974')
        None
        """
        purl = url2purl(url)
        if not purl or purl.type not in VCS_URLS_SUPPORTED_TYPES:
            return None

        version = getattr(purl, "version", None)
        if not version or not is_commit(version):
            return None

        vcs_url = purl2url(get_core_purl(purl).to_string())
        return (vcs_url, version) if vcs_url else None

    def collect_and_store_fix_commits(self):
        impacted_packages_advisories = (
            AdvisoryV2.objects.filter(impacted_packages__isnull=False)
            .prefetch_related("references", "patches", "impacted_packages")
            .distinct()
        )

        progress = LoopProgress(
            total_iterations=impacted_packages_advisories.count(), logger=self.log
        )
        for adv in progress.iter(impacted_packages_advisories.paginated(per_page=500)):
            urls = {r.url for r in adv.references.all()} | {p.patch_url for p in adv.patches.all()}
            impacted_packages = list(adv.impacted_packages.all())

            for url in urls:
                vcs_data = self.get_vcs_commit(url)
                if not vcs_data:
                    continue

                vcs_url, commit_hash = vcs_data
                package_commit_obj, _ = PackageCommitPatch.objects.get_or_create(
                    vcs_url=vcs_url, commit_hash=commit_hash
                )
                package_commit_obj.fixed_in_impacts.add(*impacted_packages)
