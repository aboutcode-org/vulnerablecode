# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from aboutcode.pipeline import LoopProgress
from django.db import transaction

from vulnerabilities.importers import IMPORTERS_REGISTRY
from vulnerabilities.models import Advisory
from vulnerabilities.models import Alias
from vulnerabilities.pipelines import VulnerableCodePipeline


class AddAdvisoryID(VulnerableCodePipeline):
    """
    Pipeline to map CVEs from VulnerabilitySeverity to corresponding Advisories with CVSS3.1 scores.
    """

    pipeline_id = "add_advisory_id"

    @classmethod
    def steps(cls):
        return (cls.add_advisory_id,)

    def add_advisory_id(self):

        advisories = Advisory.objects.all()

        advisories_to_update = []

        batch_size = 500

        progress = LoopProgress(total_iterations=advisories.count(), logger=self.log)

        for advisory in progress.iter(advisories.iterator(chunk_size=batch_size)):
            importer_name = advisory.created_by
            aliases = Alias.objects.filter(advisories=advisory).values_list("alias", flat=True)
            advisory_id = IMPORTERS_REGISTRY[importer_name].get_advisory_id(aliases=aliases)
            advisory.advisory_id = advisory_id
            advisories_to_update.append(advisory)
            if len(advisories_to_update) >= batch_size:
                self.do_bulk_update(advisories_to_update)
                advisories_to_update = []
        self.do_bulk_update(advisories_to_update)
        self.log(f"Pipeline [{self.pipeline_name}] completed.")

    def do_bulk_update(self, advisories_to_update):
        Advisory.objects.bulk_update(advisories_to_update, ["advisory_id"])
        self.log(f"Updated {len(advisories_to_update)} advisories with advisory_id.")
