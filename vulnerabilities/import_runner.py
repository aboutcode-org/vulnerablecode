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

# These _inserter classes are used to instantiate model objects.
# Frozen dataclass  store args required to store instantiate
# model objects, this way model objects can be hashed indirectly which
# is required in this implementation.


@dataclasses.dataclass(frozen=True)
class VulnerabilityReferenceInserter:
    vulnerability: models.Vulnerability
    reference_id: Optional[str] = ""
    url: Optional[str] = ""

    def __post_init__(self):
        if not any([self.reference_id, self.url]):
            raise TypeError("VulnerabilityReferenceInserter expects either reference_id or url")

    def to_model_object(self):
        return models.VulnerabilityReference(**dataclasses.asdict(self))


# These _inserter classes are used to instantiate model objects.
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
            process_advisories(data_source)
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


def process_advisories(data_source: DataSource) -> None:
    bulk_create_vuln_refs = set()
    bulk_create_vuln_pkg_refs = set()
    # Treat updated_advisories and added_advisories as same. Eventually
    # we want to  refactor all data sources to  provide advisories via a
    # single method.
    advisory_batches = chain(data_source.updated_advisories(), data_source.added_advisories())
    for batch in advisory_batches:
        for advisory in batch:
            try:
                vuln, vuln_created = _get_or_create_vulnerability(advisory)
                for vuln_ref in advisory.vuln_references:
                    ref = VulnerabilityReferenceInserter(
                        vulnerability=vuln,
                        url=vuln_ref.url,
                        reference_id=vuln_ref.reference_id,
                    )

                    if vuln_created or not vuln_ref_exists(vuln, vuln_ref.url, vuln_ref.reference_id):
                        # A vulnerability reference can't exist if the vulnerability is just created so
                        # insert it
                        bulk_create_vuln_refs.add(ref)

                for purl in chain(advisory.impacted_package_urls, advisory.resolved_package_urls):
                    pkg, pkg_created = _get_or_create_package(purl)
                    is_vulnerable = purl in advisory.impacted_package_urls
                    pkg_vuln_ref = PackageRelatedVulnerabilityInserter(
                        vulnerability=vuln, is_vulnerable=is_vulnerable, package=pkg
                    )

                    if vuln_created or pkg_created:
                        bulk_create_vuln_pkg_refs.add(pkg_vuln_ref)
                        # A vulnerability-package relationship does not exist already if either the
                        # vulnerability or the package is just created.

                    else:
                        # insert only if it there is no existing vulnerability-package relationship.
                        existing_ref = get_vuln_pkg_refs(vuln, pkg)
                        if not existing_ref:
                            bulk_create_vuln_pkg_refs.add(pkg_vuln_ref)

                        else:
                            # This handles conflicts between existing data and obtained data
                            if existing_ref[0].is_vulnerable != pkg_vuln_ref.is_vulnerable:
                                handle_conflicts([existing_ref[0], pkg_vuln_ref.to_model_object()])
                                existing_ref.delete()
            except Exception as e:
                # TODO: store error but continue
                logger.error(f"Failed to process advisory: {advisory!r}:\n" +  traceback.format_exc())

    models.VulnerabilityReference.objects.bulk_create(
        [i.to_model_object() for i in bulk_create_vuln_refs]
    )

    # find_conflicting_relations handles in-memory conflicts
    conflicts = find_conflicting_relations(bulk_create_vuln_pkg_refs)

    models.PackageRelatedVulnerability.objects.bulk_create(
        [i.to_model_object() for i in bulk_create_vuln_pkg_refs if i not in conflicts]
    )

    handle_conflicts([i.to_model_object() for i in conflicts])


def find_conflicting_relations(
    relations: Set[Set[PackageRelatedVulnerabilityInserter]],
) -> Set[PackageRelatedVulnerabilityInserter]:

    # Chop off `is_vulnerable` flag from PackageRelatedVulnerabilityInserter and create a list of
    # tuples of format (rel.package, rel.vulnerability)

    relation_tuples = [(rel.package, rel.vulnerability) for rel in relations]
    relation_counter = Counter(relation_tuples).most_common()

    # If a (rel.package, rel.vulnerability) occurs twice then that means the
    # PackageRelatedVulnerabilityInserter objects
    # (rel.package, rel.vulnerability, is_vulnerable=True) and
    # (rel.package, rel.vulnerability, is_vulnerable=False) both existed which is conflicting data.
    # We detect and return these conflicts.

    conflicts = set()
    for rel, count in relation_counter:
        if count < 2:
            # All the subsequent entries from here on would have count == 1 which is of no interest
            # since conflicts exist in pairs with `is_vulnerable=True` and `is_vulnerable=False`.
            break

        # `rel` is of format (pkg, vuln)
        conflicts.add(
            PackageRelatedVulnerabilityInserter(
                vulnerability=rel[1], package=rel[0], is_vulnerable=True
            )
        )

        conflicts.add(
            PackageRelatedVulnerabilityInserter(
                vulnerability=rel[1], package=rel[0], is_vulnerable=False
            )
        )

    return conflicts


def handle_conflicts(conflicts):
    conflicts = serializers.serialize("json", [i for i in conflicts])
    models.ImportProblem.objects.create(conflicting_model=conflicts)


def _get_or_create_vulnerability(
    advisory: Advisory,
) -> Tuple[models.Vulnerability, bool]:

    if advisory.cve_id:
        query_kwargs = {"cve_id": advisory.cve_id}
    elif advisory.summary:
        query_kwargs = {"summary": advisory.summary}
    else:
        return models.Vulnerability.objects.create(), True
    
    try:
        vuln, created = models.Vulnerability.objects.get_or_create(**query_kwargs)
        # Eventually we only want to keep summary from NVD and ignore other descriptions.
        if advisory.summary and vuln.summary != advisory.summary:
            vuln.summary = advisory.summary
            vuln.save()
        return vuln, created

    except Exception:
        logger.error(f"Failed to _get_or_create_vulnerability: {query_kwargs!r}:\n" +  traceback.format_exc())
        raise


def _get_or_create_package(p: PackageURL) -> Tuple[models.Package, bool]:
    version = p.version

    query_kwargs = {
        "name": packageurl.normalize_name(p.name, p.type, encode=True),
        "version": version,
        "type": packageurl.normalize_type(p.type, encode=True),
    }

    if p.namespace:
        query_kwargs["namespace"] = packageurl.normalize_namespace(p.namespace, p.type, encode=True)

    if p.qualifiers:
        query_kwargs["qualifiers"] = packageurl.normalize_qualifiers(p.qualifiers, encode=False)

    if p.subpath:
        query_kwargs["subpath"] = packageurl.normalize_subpath(p.subpath, encode=True)

    return models.Package.objects.get_or_create(**query_kwargs)


def _package_url_to_package(purl: PackageURL) -> models.Package:
    p = models.Package()
    p.set_package_url(purl)
    return p
