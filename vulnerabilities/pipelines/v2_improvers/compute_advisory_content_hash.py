#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from aboutcode.pipeline import LoopProgress

from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines import VulnerableCodePipeline
from vulnerabilities.utils import compute_advisory_content


class ComputeAdvisoryContentHash(VulnerableCodePipeline):
    """Compute Advisory Content Hash for Advisory."""

    pipeline_id = "compute_advisory_content_hash_v2"

    @classmethod
    def steps(cls):
        return (cls.compute_advisory_content_hash,)

    def compute_advisory_content_hash(self):
        """Compute Advisory Content Hash for Advisory."""

        advisories = AdvisoryV2.objects.latest_per_avid().filter(advisory_content_hash__isnull=True)

        advisories_count = advisories.count()

        progress = LoopProgress(
            total_iterations=advisories_count,
            logger=self.log,
            progress_step=1,
        )

        to_update = []
        batch_size = 5000

        for advisory in progress.iter(advisories.iterator(chunk_size=batch_size)):
            advisory.advisory_content_hash = compute_advisory_content(advisory)
            to_update.append(advisory)

            if len(to_update) >= batch_size:
                AdvisoryV2.objects.bulk_update(
                    to_update,
                    ["advisory_content_hash"],
                    batch_size=batch_size,
                )
                to_update.clear()

        if to_update:
            AdvisoryV2.objects.bulk_update(
                to_update,
                ["advisory_content_hash"],
                batch_size=batch_size,
            )

        self.log("Finished computing advisory_content_hash")
