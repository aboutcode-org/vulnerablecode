# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import time

import requests

from vulnerabilities.models import AdvisoryReference
from vulnerabilities.pipelines import VulnerableCodePipeline


class ArchiveImproverPipeline(VulnerableCodePipeline):
    """
    Archive Improver Pipeline
    """

    pipeline_id = "archive_improver_pipeline"

    @classmethod
    def steps(cls):
        return (cls.archive_urls,)

    def archive_urls(self):
        """Get and stores archive URLs for AdvisoryReferences, flagging missing ones as NO_ARCHIVE"""
        advisory_refs = (
            AdvisoryReference.objects.filter(archive_url__isnull=True)
            .exclude(archive_url="NO_ARCHIVE")
            .only("id", "url")
        )

        for advisory_ref in advisory_refs:
            url = advisory_ref.url
            if not url or not url.startswith("http"):
                continue

            archive_url = self.get_archival(url)
            if not archive_url:
                AdvisoryReference.objects.filter(id=advisory_ref.id).update(
                    archive_url="NO_ARCHIVE"
                )
                self.log(f"URL unreachable or returned no archive url: {url}")
                continue
            self.log(f"Found Archived Reference URL: {archive_url}")
            AdvisoryReference.objects.filter(id=advisory_ref.id).update(archive_url=archive_url)

    def get_archival(self, url):
        self.log(f"Searching for archive URL for this Reference URL: {url}")
        try:
            archive_response = requests.get(
                url=f"https://web.archive.org/web/{url}", allow_redirects=True
            )
            time.sleep(30)
            if archive_response.status_code == 200:
                return archive_response.url
            elif archive_response.status_code == 403:
                self.log(f"Wayback Machine permission denied for '{url}'.")
        except requests.RequestException as e:
            self.log(f"Error checking existing archival: {e}")
