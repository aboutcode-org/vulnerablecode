#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.models import PackageCommitPatch, Patch
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import fetch_response


class FetchPatchURLImproverPipeline(VulnerableCodePipeline):
    """FetchPatchURL Improver Pipeline"""

    pipeline_id = "fetch_patch_url"
    precedence = 200

    @classmethod
    def steps(cls):
        return (
            cls.collect_patch_text,
        )

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
            PackageCommitPatch.objects.filter(patch_text__isnull=True).count() +
            Patch.objects.filter(patch_text__isnull=True).count()
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

def generate_patch_url(vcs_url, commit_hash):
    """
    Generate patch URL from VCS URL and commit hash.
    """
    if not vcs_url or not commit_hash:
        return None

    vcs_url = vcs_url.rstrip("/")

    if vcs_url.startswith("https://github.com"):
        return f"{vcs_url}/commit/{commit_hash}.patch"
    elif vcs_url.startswith("https://gitlab.com"):
        return f"{vcs_url}/-/commit/{commit_hash}.patch"
    elif vcs_url.startswith("https://bitbucket.org"):
        return f"{vcs_url}/-/commit/{commit_hash}/raw"
    elif vcs_url.startswith("https://git.kernel.org"):
        return f"{vcs_url}.git/patch/?id={commit_hash}"
    return
