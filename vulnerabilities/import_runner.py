#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

import dataclasses
import datetime
import logging
from itertools import chain
from typing import Dict
from typing import List
from typing import Set
from typing import Tuple
from typing import Optional
from typing import Sequence

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
class VulnerabilityReference_inserter:
    vulnerability: models.Vulnerability
    reference_id: Optional[str] = ''
    url:  Optional[str] = ''

    def __post_init__(self):
        if not any([self.reference_id, self.url]):
            raise TypeError(
                "VulnerabilityReference_inserter expects either reference_id or url")

    def to_model_object(self):
        return models.VulnerabilityReference(**dataclasses.asdict(self))

# These _inserter classes are used to instantiate model objects.
# Frozen dataclass  store args required to store instantiate
# model objects, this way model objects can be hashed indirectly which
# is required in this implementation.


@dataclasses.dataclass(frozen=True)
class PackageRelatedVulnerability_inserter:
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
        logger.debug(f'Starting import for {self.importer.name}.')
        data_source = self.importer.make_data_source(
            self.batch_size, cutoff_date=cutoff_date)
        with data_source:
            _process_added_advisories(data_source)
            _process_updated_advisories(data_source)
        self.importer.last_run = datetime.datetime.now(
            tz=datetime.timezone.utc)
        self.importer.data_source_cfg = dataclasses.asdict(data_source.config)
        self.importer.save()

        logger.debug(f'Successfully finished import for {self.importer.name}.')


def _process_updated_advisories(data_source: DataSource) -> None:
    """
    TODO: Break this method into smaller functions
    """
    bulk_create_vuln_refs = set()
    bulk_create_vuln_pkg_refs = set()
    for batch in data_source.updated_advisories():
        for advisory in batch:

            vuln, vuln_created, references = _create_vulnerability_and_references(
                advisory)
            bulk_create_vuln_refs.update(references)
            inew_refs = _create_pkg_vuln_refs(
                vuln, vuln_created, advisory.impacted_package_urls, is_vulnerable=True)
            rnew_refs = _create_pkg_vuln_refs(
                vuln, vuln_created, advisory.resolved_package_urls, is_vulnerable=False)
            bulk_create_vuln_pkg_refs.update(inew_refs.union(rnew_refs))

    models.VulnerabilityReference.objects.bulk_create(
        [i.to_model_object() for i in bulk_create_vuln_refs])
    models.PackageRelatedVulnerability.objects.bulk_create(
        [i.to_model_object() for i in bulk_create_vuln_pkg_refs])


def _process_added_advisories(data_source: DataSource) -> None:
    for batch in data_source.added_advisories():
        try:
            impacted, resolved = _collect_package_urls(batch)
            impacted, resolved = _bulk_insert_packages(impacted, resolved)

            vulnerabilities = _insert_vulnerabilities_and_references(batch)

            _bulk_insert_impacted_and_resolved_packages(
                batch, vulnerabilities, impacted, resolved)
        except (DataError, RuntimeError) as e:
            # FIXME This exception might happen when the max. length of a DB column is exceeded.
            # Skipping an entire batch because one version number might be too long is obviously a
            # terrible way to handle this case.
            logger.exception(e)


def _create_vulnerability_and_references(advisory: Advisory):
    vuln, vuln_created = _get_or_create_vulnerability(advisory)
    vuln_references = set()

    if vuln_created:
        # This means vulnerability didn't previously exist in the db, so bulk create
        # is used without any hesitation
        for id_ in set(advisory.reference_ids):
            vuln_references.add(VulnerabilityReference_inserter(
                vulnerability=vuln, reference_id=id_))

        for url in set(advisory.reference_urls):
            vuln_references.add(VulnerabilityReference_inserter(
                vulnerability=vuln, url=url))

    else:
        vuln_refs_qs = models.VulnerabilityReference.objects.filter(
            vulnerability=vuln)
        vuln_ids = {ref.reference_id for ref in vuln_refs_qs}
        vuln_urls = {ref.url for ref in vuln_refs_qs}

        for id_ in advisory.reference_ids:
            # Add the item preventing duplicates pass to through.
            if id_ not in vuln_ids:
                vuln_ids.add(id_)
                vuln_references.add(VulnerabilityReference_inserter(
                    vulnerability=vuln, reference_id=id_))

        for url in advisory.reference_urls:
            # Add the item preventing duplicates pass to through.
            if url not in vuln_urls:
                vuln_urls.add(url)
                vuln_references.add(VulnerabilityReference_inserter(
                    vulnerability=vuln, url=url))

    return vuln, vuln_created, vuln_references


def _create_pkg_vuln_refs(vuln: models.Vulnerability, vuln_created: bool, purls: Sequence[PackageURL], is_vulnerable: bool):  # nopep8
    new_refs, updated_refs = set(), set()
    for purl in purls:
        pkg, pkg_created = _get_or_create_package(purl)
        vuln_pkg_ref = PackageRelatedVulnerability_inserter(
            package=pkg, vulnerability=vuln, is_vulnerable=is_vulnerable)
        if pkg_created or vuln_created:
            new_refs.add(vuln_pkg_ref)

        else:
            qs = models.PackageRelatedVulnerability.objects.filter(
                package=pkg, vulnerability=vuln)
            if not qs:
                new_refs.add(vuln_pkg_ref)
            else:
                # Note: PackageRelatedVulnerability has constraints
                # unique_together = ('package', 'vulnerability', 'is_vulnerable')
                # This fact is used below.
                vuln_impact = {i.is_vulnerable for i in qs}
                if len(vuln_impact) == 2 or is_vulnerable not in vuln_impact:
                    conflicts = [i for i in qs]
                    conflicts.append(vuln_pkg_ref.to_model_object())
                    handle_conflicts(conflicts)
                    qs.delete()

    return new_refs


def handle_conflicts(conflicts):
    conflicts = serializers.serialize('json', [i for i in conflicts])
    models.ImportProblem.objects.create(conflicting_model=conflicts)


def _get_or_create_vulnerability(advisory: Advisory) -> Tuple[models.Vulnerability, bool]:
    if advisory.cve_id:
        query_kwargs = {'cve_id': advisory.cve_id}
    elif advisory.summary:
        query_kwargs = {'summary': advisory.summary}
    else:
        return models.Vulnerability.objects.create(), True

    vuln, created = models.Vulnerability.objects.get_or_create(**query_kwargs)

    if advisory.summary and vuln.summary != advisory.summary:
        vuln.summary = advisory.summary
        vuln.save()

    return vuln, created


def _get_or_create_package(p: PackageURL) -> Tuple[models.Package, bool]:
    version = p.version

    query_kwargs = {
        'name': packageurl.normalize_name(p.name, p.type, encode=True),
        'version': version,
        'type': packageurl.normalize_type(p.type, encode=True),
    }

    if p.namespace:
        query_kwargs['namespace'] = packageurl.normalize_namespace(
            p.namespace, p.type, encode=True)

    if p.qualifiers:
        query_kwargs['qualifiers'] = packageurl.normalize_qualifiers(
            p.qualifiers, encode=False)

    if p.subpath:
        query_kwargs['subpath'] = packageurl.normalize_subpath(
            p.subpath, encode=True)

    return models.Package.objects.get_or_create(**query_kwargs)


def _bulk_insert_packages(
        impacted: List[PackageURL],
        resolved: List[PackageURL]
) -> Tuple[Dict[PackageURL, int], Dict[PackageURL, int]]:

    impacted_packages = models.Package.objects.bulk_create(
        [_package_url_to_package(p) for p in impacted])
    resolved_packages = models.Package.objects.bulk_create(
        [_package_url_to_package(p) for p in resolved])

    impacted_packages = dict(
        zip(impacted, [pkg.id for pkg in impacted_packages]))
    resolved_packages = dict(
        zip(resolved, [pkg.id for pkg in resolved_packages]))

    return impacted_packages, resolved_packages


def _bulk_insert_impacted_and_resolved_packages(
    batch: Set[Advisory],
    vulnerabilities: Set[models.Vulnerability],
    impacted_packages: Dict[PackageURL, int],
    resolved_packages: Dict[PackageURL, int],
) -> None:

    refs: List[models.ImpactedPackage] = []

    for advisory in batch:
        vuln = _advisory_to_vulnerability(advisory, vulnerabilities)

        for impacted_purl in advisory.impacted_package_urls:
            # TODO Figure out when/how it happens that a package is missing from the dict and fix it
            p = impacted_packages.get(impacted_purl)
            if not p:
                p = _package_url_to_package(impacted_purl)
                p.save()
                impacted_packages[impacted_purl] = p.id

            ip = models.PackageRelatedVulnerability(
                vulnerability=vuln,
                package_id=p,
                is_vulnerable=True
            )
            refs.append(ip)

        for resolved_purl in advisory.resolved_package_urls:
            # TODO Figure out when/how it happens that a package is missing from the dict and fix it
            p = resolved_packages.get(resolved_purl)
            if not p:
                p = _package_url_to_package(resolved_purl)
                p.save()
                resolved_packages[resolved_purl] = p.id

            ip = models.PackageRelatedVulnerability(
                vulnerability=vuln,
                package_id=p,
                is_vulnerable=False
            )
            refs.append(ip)

    models.PackageRelatedVulnerability.objects.bulk_create(refs)


def _insert_vulnerabilities_and_references(batch: Set[Advisory]) -> Set[models.Vulnerability]:
    """
    TODO Consider refactoring to use bulk_create() and avoid get_or_create() when possible.
    """
    vulnerabilities = set()

    for advisory in batch:
        vuln: models.Vulnerability

        if advisory.cve_id:
            vuln, created = models.Vulnerability.objects.get_or_create(
                cve_id=advisory.cve_id)
            if created and advisory.summary:
                vuln.summary = advisory.summary
                vuln.save()
        else:
            # FIXME
            # There is no way to check whether a vulnerability without a CVE ID already exists in
            # the database.
            vuln = models.Vulnerability.objects.create(
                summary=advisory.summary)

        vulnerabilities.add(vuln)

        for id_ in advisory.reference_ids:
            models.VulnerabilityReference.objects.get_or_create(
                vulnerability=vuln, reference_id=id_)

        for url in advisory.reference_urls:
            models.VulnerabilityReference.objects.get_or_create(
                vulnerability=vuln, url=url)

    return vulnerabilities


def _advisory_to_vulnerability(
        advisory: Advisory,
        vulnerabilities: Set[models.Vulnerability]
) -> models.Vulnerability:

    for v in vulnerabilities:
        if advisory.cve_id and advisory.cve_id == v.cve_id:
            return v

        if advisory.summary == v.summary:
            return v

    raise RuntimeError(f'No Vulnerability model object found for this Advisory: {advisory.summary}')


def _collect_package_urls(batch: Set[Advisory]) -> Tuple[List[PackageURL], List[PackageURL]]:
    impacted, resolved = [], []

    for advisory in batch:
        impacted.extend(advisory.impacted_package_urls)
        resolved.extend(advisory.resolved_package_urls)

    return impacted, resolved


def _package_url_to_package(purl: PackageURL) -> models.Package:
    p = models.Package()
    p.set_package_url(purl)
    return p
