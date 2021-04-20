#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import dataclasses
import datetime
import logging
from collections import Counter
from itertools import chain
import traceback
from typing import Set
from typing import Tuple
from typing import Optional

import packageurl
from django.db import DataError
from django.core import serializers

from vulnerabilities import models
from vulnerabilities.data_source import Advisory, DataSource
from vulnerabilities.data_source import PackageURL

logger = logging.getLogger(__name__)

class ImportRunner:
    """
    The ImportRunner is responsible for inserting and updating data about vulnerabilities and
    affected/unaffected/fixed packages in the database. The two main goals for the implementation
    are correctness and efficiency.

    Correctness:
        - There must be no duplicates in the database (should be enforced by the schema).
        - No valid data from the data source must be skipped or truncated.

    Efficiency:
        - Bulk inserts should be used whenever possible.
        - Checking whether a record already exists should be kept to a minimum
        (the data source should know this instead).
        - All update and select operations must use indexed columns.
    """

    def __init__(self, importer: models.Importer, batch_size: int):
        self.importer = importer
        self.batch_size = batch_size

    def run(self, cutoff_date: datetime.datetime = None) -> None:
        """
        Create a data source for the given importer and store the data retrieved in the database.

        cutoff_date - optional timestamp of the oldest data to include in the import

        NB: Data sources provide two kinds of records; vulnerabilities and packages. Vulnerabilities
        are potentially shared across many packages, from the same data source and from different
        data sources. For example, a vulnerability in the Linux kernel is mentioned by advisories
        from all Linux distributions that package this kernel version.
        """
        logger.info(f"Starting import for {self.importer.name}.")
        data_source = self.importer.make_data_source(self.batch_size, cutoff_date=cutoff_date)
        with data_source:
            self.import_run = models.ImportRun.objects.create(importer=self.importer)
            self.process_advisories(data_source)
            self.importer.last_import = self.import_run

        self.importer.last_run = datetime.datetime.now(tz=datetime.timezone.utc)
        self.importer.data_source_cfg = dataclasses.asdict(data_source.config)

        logger.info(f"Finished import for {self.importer.name}.")

    def process_advisories(self, data_source: DataSource) -> None:
        for advisory in data_source.updated_advisories():
            models.Advisory.objects.create(content=advisory.to_dict(), import_run=self.import_run)
            if self.importer.last_import and self.importer.last_import.advisory_set.filter(content=advisory.to_dict()):
                continue

            vuln, _ = _get_or_create_vulnerability(advisory)
            for packageurl in  advisory.impacted_package_urls:
                pkg, _ = _get_or_create_package(packageurl)
                models.PackageRelatedVulnerability.objects.get_or_create(
                    package=pkg,
                    is_vulnerable=True,
                    vulnerability=vuln
                )
            
            for packageurl in  advisory.resolved_package_urls:
                pkg, _ = _get_or_create_package(packageurl)
                models.PackageRelatedVulnerability.objects.get_or_create(
                    package=pkg,
                    is_vulnerable=False,
                    vulnerability=vuln
                )
            
            for reference in advisory.references:
                models.VulnerabilityReference.objects.get_or_create(
                    vulnerability=vuln,
                    reference_id=reference.reference_id,
                    url=reference.url
                )

def _get_or_create_vulnerability(
    advisory: Advisory,
) -> Tuple[models.Vulnerability, bool]:

    vuln, created = models.Vulnerability.objects.get_or_create(
        vulnerability_id=advisory.vulnerability_id
    )

    # Eventually we only want to keep summary from NVD and ignore other descriptions.
    if advisory.summary and vuln.summary != advisory.summary:
        vuln.summary = advisory.summary
        vuln.save()

    return vuln, created


def _get_or_create_package(p: PackageURL) -> Tuple[models.Package, bool]:

    query_kwargs = {}
    for key, val in p.to_dict().items():
        if not val:
            if key == "qualifiers":
                query_kwargs[key] = {}
            else:
                query_kwargs[key] = ""
        else:
            query_kwargs[key] = val

    return models.Package.objects.get_or_create(**query_kwargs)
