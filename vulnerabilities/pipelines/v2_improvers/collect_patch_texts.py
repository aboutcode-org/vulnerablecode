#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging

import requests
from aboutcode.pipeline import LoopProgress
from django.db.models import Q

from vulnerabilities.models import Patch
from vulnerabilities.pipelines import VulnerableCodePipeline


class CollectPatchTextsPipeline(VulnerableCodePipeline):
    """
    Improver pipeline to collect missing patch texts for Patch objects that have a patch_url.
    """

    pipeline_id = "collect_patch_texts_v2"
    license_expression = None

    @classmethod
    def steps(cls):
        return (cls.collect_and_store_patch_texts,)

    def collect_and_store_patch_texts(self):
        patches_without_text = Patch.objects.filter(
            Q(patch_url__isnull=False) & ~Q(patch_url=""),
            Q(patch_text__isnull=True) | Q(patch_text=""),
        )

        self.log(f"Processing {patches_without_text.count():,d} patches to collect text.")

        updated_patch_count = 0
        progress = LoopProgress(total_iterations=patches_without_text.count(), logger=self.log)

        for patch in progress.iter(patches_without_text.iterator(chunk_size=500)):
            raw_url = get_raw_patch_url(patch.patch_url)
            if not raw_url:
                continue

            try:
                response = requests.get(raw_url, timeout=10)
                if response.status_code == 200:
                    patch.patch_text = response.text
                    patch.save()
                    updated_patch_count += 1
                else:
                    self.log(
                        f"Failed to fetch patch from {raw_url}: Status {response.status_code}",
                        level=logging.WARNING if response.status_code < 500 else logging.ERROR,
                    )
            except requests.RequestException as e:
                self.log(f"Error fetching patch from {raw_url}: {e}", level=logging.ERROR)

        self.log(f"Successfully collected text for {updated_patch_count:,d} Patch entries.")


def get_raw_patch_url(url):
    """
    Return a fetchable raw patch URL from common VCS hosting URLs,
    or the URL itself if it already points to a .patch or .diff file.
    Return None if the URL type is not recognized.
    """
    if not url:
        return None

    url = url.strip()

    if "github.com" in url and "/commit/" in url and not url.endswith(".patch"):
        return f"{url}.patch"

    if "github.com" in url and "/pull/" in url and not url.endswith(".patch"):
        return f"{url}.patch"

    if "gitlab.com" in url and "/commit/" in url and not url.endswith(".patch"):
        return f"{url}.patch"

    if "gitlab.com" in url and "/merge_requests/" in url and not url.endswith(".patch"):
        return f"{url}.patch"

    if url.endswith(".patch") or url.endswith(".diff"):
        return url

    return None
