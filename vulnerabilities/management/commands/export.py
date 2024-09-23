#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging
from itertools import groupby
from pathlib import Path

import saneyaml
from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from packageurl import PackageURL

from aboutcode import hashid
from vulnerabilities.models import Package

logger = logging.getLogger(__name__)


def serialize_severity(sev):
    # inlines refs
    ref = sev.reference
    sevref = {
        "url": ref.url,
        "reference_type": ref.reference_type,
        "reference_id": ref.reference_id,
    }

    return {
        "score": sev.value,
        "scoring_system": sev.scoring_system,
        "scoring_elements": sev.scoring_elements,
        "published_at": sev.published_at,
        "reference": sevref,
    }


def serialize_vulnerability(vuln):
    """
    Return a plain data mapping seralized from ``vuln`` Vulnerability instance.
    """
    aliases = list(vuln.aliases.values_list("alias", flat=True))
    severities = [serialize_severity(sev) for sev in vuln.severities]
    weaknesses = [wkns.cwe for wkns in vuln.weaknesses.all()]

    references = list(
        vuln.references.values(
            "url",
            "reference_type",
            "reference_id",
        )
    )

    return {
        "vulnerability_id": vuln.vcid,
        "aliases": aliases,
        "summary": vuln.summary,
        "severities": severities,
        "weaknesses": weaknesses,
        "references": references,
    }


class Command(BaseCommand):
    help = """Export vulnerability and package data as YAML for use in FederatedCode

    This command exports the data in a tree of directories and YAML files designed such that
    it is possible to access directly a vulnerability data file by only knowing its VCID, and that
    it is possible to access directly the package data files by only knowing its PURL.
    """

    def add_arguments(self, parser):
        parser.add_argument(
            "path",
            help="Path to a directory where to export data.",
        )

    def handle(self, *args, **options):
        if path := options["path"]:
            base_path = Path(path)

        if not path or not base_path.is_dir():
            raise CommandError("Enter a valid directory path")

        self.stdout.write("Exporting vulnerablecode Package and Vulnerability data.")
        self.export_data(base_path)
        self.stdout.write(self.style.SUCCESS(f"Successfully exported data to {base_path}."))

    def export_data(self, base_path: Path):
        """
        Export vulnerablecode data to ``base_path``.`
        """
        i = 0
        seen_vcid = set()

        for i, (purl_without_version, package_versions) in enumerate(packages_by_type_ns_name(), 1):
            pkg_version = None
            try:
                package_urls = []
                package_vulnerabilities = []
                for pkg_version in package_versions:
                    purl = pkg_version.package_url
                    package_urls.append(purl)
                    package_data = {
                        "purl": purl,
                        "affected_by_vulnerabilities": list(
                            pkg_version.affected_by.values_list("vulnerability_id", flat=True)
                        ),
                        "fixing_vulnerabilities": list(
                            pkg_version.fixing.values_list("vulnerability_id", flat=True)
                        ),
                    }
                    package_vulnerabilities.append(package_data)

                    for vuln in pkg_version.vulnerabilities.all():
                        vcid = vuln.vulnerability_id
                        # do not write twice the same file
                        if vcid in seen_vcid:
                            continue

                        seen_vcid.add(vcid)
                        vulnerability = serialize_vulnerability(vuln)
                        vpath = hashid.get_vcid_yml_file_path(vcid)
                        write_file(base_path=base_path, file_path=vpath, data=vulnerability)
                        if (lv := len(seen_vcid)) % 100 == 0:
                            self.stdout.write(f"Processed {lv} vulnerabilities. Last VCID: {vcid}")

                ppath = hashid.get_package_purls_yml_file_path(purl)
                write_file(base_path=base_path, file_path=ppath, data=package_urls)

                pvpath = hashid.get_package_vulnerabilities_yml_file_path(purl)
                write_file(base_path=base_path, file_path=pvpath, data=package_vulnerabilities)

                if i % 100 == 0:
                    self.stdout.write(f"Processed {i} package. Last PURL: {purl_without_version}")

            except Exception as e:
                raise Exception(f"Failed to process Package: {pkg_version}") from e

        self.stdout.write(f"Exported data for: {i} package and {len(seen_vcid)} vulnerabilities.")


def by_purl_type_ns_name(package):
    """
    Key function to sort packages by type, namespace and name
    """
    return package.type, package.namespace, package.name


def packages_by_type_ns_name():
    """
    Return a two-level iterator over all Packages grouped-by package, ignoring version.
    """
    qs = (
        Package.objects.order_by("type", "namespace", "name", "version")
        .prefetch_related(
            "vulnerabilities",
            "vulnerabilities__references",
            "vulnerabilities__weaknesses",
            "vulnerabilities__references__vulnerabilityseverity_set",
        )
        .paginated()
    )

    for tp_ns_name, packages in groupby(qs, key=by_purl_type_ns_name):
        yield PackageURL(*tp_ns_name), packages


def write_file(base_path: Path, file_path: Path, data: dict):
    """
    Write the ``data`` as YAML to the ``file_path`` in the ``base_path`` root directory.
    Create directories in the path as needed.
    """
    write_to = base_path / file_path
    write_to.parent.mkdir(parents=True, exist_ok=True)
    with open(write_to, encoding="utf-8", mode="w") as f:
        f.write(saneyaml.dump(data))
