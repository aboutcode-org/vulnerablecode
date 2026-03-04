#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.models import PackageCommitPatch
from vulnerabilities.models import Patch
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import fetch_response
from vulnerabilities.utils import generate_patch_url


class FetchPatchURLImproverPipeline(VulnerableCodePipeline):
    """FetchPatchURL Improver Pipeline"""

    pipeline_id = "fetch_patch_url"
    precedence = 200

    @classmethod
    def steps(cls):
        return (cls.collect_patch_text,)

    def fetch_patch_content(self, url):
        """
        Fetches the text content of a patch from a URL.
        """
        if not url:
            return None

        self.log(f"Fetching `{url}`")

        response = fetch_response(url)
        if response:
            return response.text.replace("\x00", "")

        self.log(f"Skipping {url} due to fetch failure.")
        return None

    def advisories_count(self) -> int:
        return (
            PackageCommitPatch.objects.filter(patch_text__isnull=True).count()
            + Patch.objects.filter(patch_text__isnull=True).count()
        )

    def collect_patch_text(self):
        for pcp in PackageCommitPatch.objects.filter(patch_text__isnull=True):
            patch_url = generate_patch_url(pcp.vcs_url, pcp.commit_hash)
            content = self.fetch_patch_content(patch_url)
            if not content:
                continue
            pcp.patch_text = content
            pcp.save()

        for patch in Patch.objects.filter(patch_text__isnull=True):
            content = self.fetch_patch_content(patch.patch_url)
            if not content:
                continue

            patch.patch_text = content
            patch.save()
