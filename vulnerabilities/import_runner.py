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
from typing import List, Union
from typing import Mapping
from typing import Sequence
from typing import Set
from typing import Tuple

from django.db import IntegrityError
from django.db import transaction

from vulnerabilities import models
from vulnerabilities.data_source import Advisory
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
    def __init__(self, importer, batch_size=None):
        self.importer = importer
        self.batch_size = batch_size

    def run(self, cutoff_date=None) -> None:
        """
        Create a data source for the given importer and store the data retrieved in the database.

        NB: Data sources provide two kinds of records; vulnerabilities and packages. Vulnerabilities are potentially
        shared across many packages, from the same data source and from different data sources. For example, a
        vulnerability in the Linux kernel is mentioned by advisories from all Linux distributions that package this
        kernel version.
        """
        logger.debug(f'Starting import for {self.importer.name}.')
        data_source = self.importer.make_data_source(cutoff_date=cutoff_date, batch_size=self.batch_size)

        with data_source as ds:
            _process_new_advisories(ds)
            _process_updated_advisories(ds)

        self.importer.last_run = datetime.datetime.utcnow()
        self.importer.save()

        logger.debug(f'Successfully finished import for {self.importer.name}.')


def _process_new_advisories(data_source):
    for batch in data_source.added_advisories():
        impacted, resolved = _collect_purls(batch)
        impacted, resolved = _bulk_insert_packages(impacted, resolved)

        vulnerabilities = _insert_vulnerabilities_and_references(batch)

        _bulk_insert_impacted_and_resolved_packages(batch, vulnerabilities, impacted, resolved)


def _process_updated_advisories(data_source):
    """
    TODO: Make efficient; Current implementation needs way too many DB queries.
    """
    for batch in data_source.updated_advisories():
        for advisory in batch:
            vuln, _ = _get_or_create_vulnerability(advisory)

            for url in advisory.references:
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
    query_kwargs = {}

    if advisory.cve_id:
        query_kwargs['cve_id'] = advisory.cve_id
    else:
        query_kwargs = {'summary': advisory.summary}
    vuln, created = models.Vulnerability.objects.get_or_create(**query_kwargs)

    if not created and vuln.summary != advisory.summary:
        vuln.summary = advisory.summary
        vuln.save()

    return vuln, created


def _get_or_create_package(p: PackageURL) -> Tuple[models.Package, bool]:
    query_kwargs = {'name': p.name, 'version': p.version, 'type': p.type}
    if p.namespace:
        query_kwargs['namespace'] = p.namespace

    pkg, created = models.Package.objects.get_or_create(**query_kwargs)
    if created:
        dirty = False
        if p.qualifiers:
            pkg.qualifiers = p.qualifiers
            dirty = True
        if p.subpath:
            pkg.subpath = p.subpath
            dirty = True
        if dirty:
            pkg.save()

    return pkg, created


# FIXME
# Accepting Set[str], Set[str] instead of Set[PackageURL] Set[PackageURL]
# is a workaround until https://github.com/package-url/packageurl-python/issues/28 is fixed.
def _bulk_insert_packages(
        impacted: Set[str],
        resolved: Set[str]
) -> Tuple[Mapping[str, models.Package], Mapping[str, models.Package]]:

    packages = [_package_url_to_package(p) for p in impacted.union(resolved)]
    packages = models.Package.objects.bulk_create(packages)

    # impacted = {str(p) for p in impacted}
    # resolved = {str(p) for p in resolved}

    impacted_packages, resolved_packages = {}, {}

    for pkg in packages:
        purl = pkg.package_url

        if purl in impacted:
            impacted_packages[purl] = pkg
        elif purl in resolved:
            resolved_packages[purl] = pkg

    return impacted_packages, resolved_packages


def _bulk_insert_impacted_and_resolved_packages(
    batch: Sequence[Advisory],
    vulnerabilitites: Set[models.Vulnerability],
    impacted_packages: Mapping[str, models.Package],
    resolved_packages: Mapping[str, models.Package],
) -> None:

    impacted_refs: List[models.ImpactedPackage] = []
    resolved_refs: List[models.ResolvedPackage] = []

    for advisory in batch:
        vuln = _advisory_to_vulnerability(advisory, vulnerabilitites)
        vulnerabilitites.remove(vuln)  # minor optimization

        for impacted_purl in advisory.impacted_purls:
            ip = models.ImpactedPackage(
                vulnerability=vuln,
                package=impacted_packages[impacted_purl]
            )
            impacted_refs.append(ip)

        for resolved_purl in advisory.resolved_purls:
            ip = models.ResolvedPackage(
                vulnerability=vuln,
                package=resolved_packages[str(resolved_purl)]
            )
            resolved_refs.append(ip)

    models.ImpactedPackage.objects.bulk_create(impacted_refs)
    models.ResolvedPackage.objects.bulk_create(resolved_refs)


@transaction.atomic
def _insert_vulnerabilities_and_references(batch: Sequence[Advisory]) -> Set[models.Vulnerability]:
    """
    TODO Consider refactoring to use bulk_create() and avoid get_or_create() when possible.
    """
    vulnerabilities = set()

    for advisory in batch:
        vuln: models.Vulnerability

        if advisory.cve_id:
            vuln, created = models.Vulnerability.objects.get_or_create(cve_id=advisory.cve_id)
            if created:
                vuln.summary = advisory.summary
                vuln.save()
        else:
            # FIXME
            # There is no way to check whether a vulnerability without a CVE ID already exists in the database.
            vuln = models.Vulnerability.objects.create(summary=advisory.summary)

        vulnerabilities.add(vuln)

        for url in advisory.references:
            try:
                models.VulnerabilityReference.objects.create(vulnerability=vuln, url=url)
            except IntegrityError:
                # This vulnerability reference already exists, nothing to do.
                # TODO Find a more efficient way to do this rather than trying and ignoring any errors.
                pass

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


# FIXME
# Returning Tuple[Set[str], Set[str]] instead of Tuple[Set[PackageURL], Set[PackageURL]]
# is a workaround until https://github.com/package-url/packageurl-python/issues/28 is fixed.
# When changing this, also rename the function to "_collect_package_urls".
def _collect_purls(batch: Sequence[Advisory]) -> Tuple[Set[str], Set[str]]:
    impacted, resolved = set(), set()

    for advisory in batch:
        # FIXME Workaround until https://github.com/package-url/packageurl-python/issues/28 is fixed
        s = {str(p) for p in advisory.impacted_package_urls}
        impacted.update(s)

        # FIXME Workaround until https://github.com/package-url/packageurl-python/issues/28 is fixed
        s = {str(p) for p in advisory.resolved_package_urls}
        resolved.update(s)

    return impacted, resolved


def _package_url_to_package(purl: Union[PackageURL, str]) -> models.Package:
    # FIXME
    # Remove support for passing purls as strings after
    # https://github.com/package-url/packageurl-python/issues/28 got fixed
    if isinstance(purl, str):
        purl = PackageURL.from_string(purl)

    return models.Package(
        name=purl.name,
        type=purl.type,
        version=purl.version,
        namespace=purl.namespace,
        qualifiers=purl.qualifiers,
        subpath=purl.subpath,
    )
