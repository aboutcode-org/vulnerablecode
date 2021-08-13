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
from typing import Tuple
from typing import Set


from vulnerabilities import models
from vulnerabilities.data_source import Advisory
from vulnerabilities.data_source import PackageURL
from vulnerabilities.data_inference import Inference
from vulnerabilities.data_inference import MAX_CONFIDENCE
from vulnerabilities.improve_runner import process_inferences

logger = logging.getLogger(__name__)

# This *Inserter class is used to instantiate model objects.
# Frozen dataclass  store args required to store instantiate
# model objects, this way model objects can be hashed indirectly which
# is required in this implementation.


@dataclasses.dataclass(frozen=True)
class PackageRelatedVulnerabilityInserter:
    vulnerability: models.Vulnerability
    is_vulnerable: bool
    package: models.Package

    def to_model_object(self):
        return models.PackageRelatedVulnerability(**dataclasses.asdict(self))


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

    def __init__(self, importer: models.Importer):
        self.importer = importer

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
        data_source = self.importer.make_data_source(cutoff_date=cutoff_date)
        with data_source:
            advisories = data_source.updated_advisories()
            process_advisories("importer", advisories)
        self.importer.last_run = datetime.datetime.now(tz=datetime.timezone.utc)
        self.importer.data_source_cfg = dataclasses.asdict(data_source.config)
        self.importer.save()

        logger.info(f"Finished import for {self.importer.name}.")


def vuln_ref_exists(vulnerability, url, reference_id):
    return models.VulnerabilityReference.objects.filter(
        vulnerability=vulnerability, reference_id=reference_id, url=url
    ).exists()


def get_vuln_pkg_refs(vulnerability, package):
    return models.PackageRelatedVulnerability.objects.filter(
        vulnerability=vulnerability,
        package=package,
    )


def process_advisories(source: str, advisories: Set[Advisory]) -> None:
    """
    Insert advisories into the database
    Advisories are treated as full confidence infererences.
    """
    inferences = [ Inference(advisory, source, MAX_CONFIDENCE) for advisory in advisories ]
    process_inferences(inferences)
