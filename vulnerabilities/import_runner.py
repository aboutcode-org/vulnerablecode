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

import datetime
import logging
from typing import Dict
from typing import List
from typing import Set
from typing import Tuple

import packageurl

from vulnerabilities import models
from vulnerabilities.data_source import Advisory, DataSource
from vulnerabilities.data_source import PackageURL

logger = logging.getLogger(__name__)


class ImportRunner:
    """
    The ImportRunner is responsible for inserting and updating data about vulnerabilities and
    affected/unaffected/fixed packages in the database. The two main goals for the implementation are correctness and
    efficiency.

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

        NB: Data sources provide two kinds of records; vulnerabilities and packages. Vulnerabilities are potentially
        shared across many packages, from the same data source and from different data sources. For example, a
        vulnerability in the Linux kernel is mentioned by advisories from all Linux distributions that package this
        kernel version.
        """
        logger.debug(f'Starting import for {self.importer.name}.')
        data_source = self.importer.make_data_source(self.batch_size, cutoff_date=cutoff_date)

        with data_source:
            _process_added_advisories(data_source)
            _process_updated_advisories(data_source)

        self.importer.last_run = datetime.datetime.now(tz=datetime.timezone.utc)
        self.importer.save()

        logger.debug(f'Successfully finished import for {self.importer.name}.')


def _process_added_advisories(data_source: DataSource) -> None:
    for batch in data_source.added_advisories():
        impacted, resolved = _collect_package_urls(batch)
        impacted, resolved = _bulk_insert_packages(impacted, resolved)

        vulnerabilities = _insert_vulnerabilities_and_references(batch)

        _bulk_insert_impacted_and_resolved_packages(batch, vulnerabilities, impacted, resolved)


def _process_updated_advisories(data_source: DataSource) -> None:
    """
    TODO: Make efficient; Current implementation needs way too many DB queries.
    """
    for batch in data_source.updated_advisories():
        for advisory in batch:
            vuln, _ = _get_or_create_vulnerability(advisory)

            for id_ in advisory.reference_ids:
                models.VulnerabilityReference.objects.get_or_create(vulnerability=vuln, reference_id=id_)

            for url in advisory.reference_urls:
                models.VulnerabilityReference.objects.get_or_create(vulnerability=vuln, url=url)

            for ipkg_url in advisory.impacted_package_urls:
                pkg, created = _get_or_create_package(ipkg_url)

                # FIXME Does not work yet due to cascading deletes.
                # if not created:
                #     qs = models.ResolvedPackage.objects.filter(vulnerability_id=vuln.id, package_id=pkg.id)
                #     if qs:
                #         qs[0].delete()

                models.ImpactedPackage.objects.get_or_create(vulnerability_id=vuln.id, package_id=pkg.id)

            for rpkg_url in advisory.resolved_package_urls:
                pkg, created = _get_or_create_package(rpkg_url)

                # FIXME Does not work yet due to cascading deletes.
                # if not created:
                #     qs = models.ImpactedPackage.objects.filter(vulnerability_id=vuln.id, package_id=pkg.id)
                #     if qs:
                #         qs[0].delete()

                models.ResolvedPackage.objects.get_or_create(vulnerability_id=vuln.id, package_id=pkg.id)


def _get_or_create_vulnerability(advisory: Advisory) -> Tuple[models.Vulnerability, bool]:
    if advisory.cve_id:
        query_kwargs = {'cve_id': advisory.cve_id}
    elif advisory.summary:
        query_kwargs = {'summary': advisory.summary}
    else:
        return models.Vulnerability.objects.create(), True

    vuln, created = models.Vulnerability.objects.get_or_create(**query_kwargs)

    if not created and vuln.summary != advisory.summary:
        vuln.summary = advisory.summary
        vuln.save()

    return vuln, created


def _get_or_create_package(p: PackageURL) -> Tuple[models.Package, bool]:
    version = packageurl.normalize_version(p.version, encode=True)

    # FIXME terrible hack, remove after https://github.com/package-url/packageurl-python/pull/30 was merged
    if len(version) > 50:
        version = version[:50]

    query_kwargs = {
        'name': packageurl.normalize_name(p.name, p.type, encode=True),
        'version': version,
        'type': packageurl.normalize_type(p.type, encode=True),
    }

    if p.namespace:
        query_kwargs['namespace'] = packageurl.normalize_namespace(p.namespace, p.type, encode=True)

    if p.qualifiers:
        query_kwargs['qualifiers'] = packageurl.normalize_qualifiers(p.qualifiers, encode=True)

    if p.subpath:
        query_kwargs['subpath'] = packageurl.normalize_subpath(p.subpath, encode=True)

    return models.Package.objects.get_or_create(**query_kwargs)


def _bulk_insert_packages(
        impacted: Set[PackageURL],
        resolved: Set[PackageURL]
) -> Tuple[Dict[PackageURL, models.Package], Dict[PackageURL, models.Package]]:

    packages = [_package_url_to_package(p) for p in impacted.union(resolved)]
    packages = models.Package.objects.bulk_create(packages)

    impacted_packages, resolved_packages = {}, {}

    for pkg in packages:
        # Unfortunately, PackageURLMixin.package_url returns a string, not a PackageURL
        purl = PackageURL.from_string(pkg.package_url)

        if purl in impacted:
            impacted_packages[purl] = pkg
        elif purl in resolved:
            resolved_packages[purl] = pkg

    return impacted_packages, resolved_packages


def _bulk_insert_impacted_and_resolved_packages(
    batch: Set[Advisory],
    vulnerabilities: Set[models.Vulnerability],
    impacted_packages: Dict[PackageURL, models.Package],
    resolved_packages: Dict[PackageURL, models.Package],
) -> None:

    impacted_refs: List[models.ImpactedPackage] = []
    resolved_refs: List[models.ResolvedPackage] = []

    for advisory in batch:
        vuln = _advisory_to_vulnerability(advisory, vulnerabilities)
        vulnerabilities.remove(vuln)  # minor optimization

        for impacted_purl in advisory.impacted_package_urls:
            # TODO Figure out when/how it happens that a package is missing from the dict and fix it
            p = impacted_packages.get(impacted_purl)
            if not p:
                p = _package_url_to_package(impacted_purl)
                p.save()
                impacted_packages[impacted_purl] = p

            ip = models.ImpactedPackage(
                vulnerability=vuln,
                package=p,
            )
            impacted_refs.append(ip)

        for resolved_purl in advisory.resolved_package_urls:
            # TODO Figure out when/how it happens that a package is missing from the dict and fix it
            p = resolved_packages.get(resolved_purl)
            if not p:
                p = _package_url_to_package(resolved_purl)
                p.save()
                resolved_packages[resolved_purl] = p

            ip = models.ResolvedPackage(
                vulnerability=vuln,
                package=p,
            )
            resolved_refs.append(ip)

    models.ImpactedPackage.objects.bulk_create(impacted_refs)
    models.ResolvedPackage.objects.bulk_create(resolved_refs)


def _insert_vulnerabilities_and_references(batch: Set[Advisory]) -> Set[models.Vulnerability]:
    """
    TODO Consider refactoring to use bulk_create() and avoid get_or_create() when possible.
    """
    vulnerabilities = set()

    for advisory in batch:
        vuln: models.Vulnerability

        if advisory.cve_id:
            vuln, created = models.Vulnerability.objects.get_or_create(cve_id=advisory.cve_id)
            if created and vuln.summary:
                vuln.summary = advisory.summary
                vuln.save()
        else:
            # FIXME
            # There is no way to check whether a vulnerability without a CVE ID already exists in the database.
            vuln = models.Vulnerability.objects.create(summary=advisory.summary)

        vulnerabilities.add(vuln)

        for id_ in advisory.reference_ids:
            models.VulnerabilityReference.objects.get_or_create(vulnerability=vuln, reference_id=id_)

        for url in advisory.reference_urls:
            models.VulnerabilityReference.objects.get_or_create(vulnerability=vuln, url=url)

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


def _collect_package_urls(batch: Set[Advisory]) -> Tuple[Set[PackageURL], Set[PackageURL]]:
    impacted, resolved = set(), set()

    for advisory in batch:
        impacted.update(advisory.impacted_package_urls)
        resolved.update(advisory.resolved_package_urls)

    return impacted, resolved


def _package_url_to_package(purl: PackageURL) -> models.Package:
    p = models.Package()
    p.set_package_url(purl)
    return p
