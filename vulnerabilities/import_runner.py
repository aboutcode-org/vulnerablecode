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
from itertools import chain
from typing import Tuple
from typing import Set

from django.db import transaction

from vulnerabilities import models
from vulnerabilities.data_source import Advisory, DataSource
from vulnerabilities.data_source import PackageURL

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
            process_advisories(advisories)
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


@transaction.atomic
def process_advisories(advisories: Set[Advisory]) -> None:
    bulk_create_vuln_pkg_refs = set()
    for advisory in advisories:
        vuln, vuln_created = _get_or_create_vulnerability(advisory)
        for vuln_ref in advisory.references:
            ref, _ = models.VulnerabilityReference.objects.get_or_create(
                vulnerability=vuln, reference_id=vuln_ref.reference_id, url=vuln_ref.url
            )

            for score in vuln_ref.severities:
                models.VulnerabilitySeverity.objects.update_or_create(
                    vulnerability=vuln,
                    scoring_system=score.system.identifier,
                    reference=ref,
                    defaults={"value": str(score.value)},
                )

        for aff_pkg_with_patched_pkg in advisory.affected_packages:
            vulnerable_package, _ = _get_or_create_package(
                aff_pkg_with_patched_pkg.vulnerable_package
            )
            patched_package = None
            if aff_pkg_with_patched_pkg.patched_package:
                patched_package, _ = _get_or_create_package(
                    aff_pkg_with_patched_pkg.patched_package
                )

            prv, _ = models.PackageRelatedVulnerability.objects.get_or_create(
                vulnerability=vuln,
                package=vulnerable_package,
            )

            if patched_package:
                prv.patched_package = patched_package
                prv.save()

    models.PackageRelatedVulnerability.objects.bulk_create(
        [i.to_model_object() for i in bulk_create_vuln_pkg_refs]
    )


def _get_or_create_vulnerability(
    advisory: Advisory,
) -> Tuple[models.Vulnerability, bool]:

    vuln, created = models.Vulnerability.objects.get_or_create(
        vulnerability_id=advisory.vulnerability_id
    )  # nopep8
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


def _package_url_to_package(purl: PackageURL) -> models.Package:
    p = models.Package()
    p.set_package_url(purl)
    return p
