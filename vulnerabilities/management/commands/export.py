#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging
import os
from hashlib import sha512
from pathlib import Path

import saneyaml
from django.core.management.base import BaseCommand
from django.core.management.base import CommandError
from packageurl import PackageURL

from vulnerabilities.models import Package

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "export vulnerablecode data"

    def add_arguments(self, parser):
        parser.add_argument("path")

    def handle(self, *args, **options):
        if options["path"]:
            git_path = Path(options["path"])
            if not git_path.is_dir():
                raise CommandError("Please enter a valid path")

            self.export_data(git_path)

        self.stdout.write(self.style.SUCCESS("Successfully exported vulnerablecode data"))

    def export_data(self, git_path):
        """
        export vulnerablecode data
        by running `python manage.py export /path/vulnerablecode-data`
        """
        self.stdout.write("Exporting vulnerablecode data")

        ecosystems = [pkg.type for pkg in Package.objects.distinct("type")]

        for ecosystem in ecosystems:
            package_files = {}  # {"package path": "data" }
            vul_files = {}  # {"vulnerability path": "data" }

            for purl in (
                Package.objects.filter(type=ecosystem)
                .prefetch_related("vulnerabilities")
                .paginated()
            ):
                purl_without_version = PackageURL(
                    type=purl.type,
                    namespace=purl.namespace,
                    name=purl.name,
                )

                # ./aboutcode-packages-ed5/maven/org.apache.log4j/log4j-core/versions/vulnerabilities.yml
                pkg_filepath = (
                    f"./aboutcode-packages-{get_purl_hash(purl_without_version)}/{purl.type}/{purl.namespace}/{purl.name}"
                    f"/versions/vulnerabilities.yml"
                )

                package_data = {
                    "purl": str(purl),
                    "affected_by_vulnerabilities": [
                        vuln.vulnerability_id for vuln in purl.affected_by
                    ],
                    "fixing_vulnerabilities": [vuln.vulnerability_id for vuln in purl.fixing],
                }

                if pkg_filepath in package_files:
                    package_files[pkg_filepath]["versions"].append(package_data)
                else:
                    package_files[pkg_filepath] = {
                        "package": str(purl_without_version),
                        "versions": [package_data],
                    }

                for vul in purl.vulnerabilities.all():
                    vulnerability_id = vul.vulnerability_id
                    # ./aboutcode-vulnerabilities-12/34/VCID-1223-3434-34343/VCID-1223-3434-34343.yml
                    vul_filepath = (
                        f"./aboutcode-vulnerabilities-{vulnerability_id[5:7]}/{vulnerability_id[10:12]}"
                        f"/{vulnerability_id}/{vulnerability_id}.yml"
                    )
                    vul_files[vul_filepath] = {
                        "vulnerability_id": vul.vulnerability_id,
                        "aliases": [alias.alias for alias in vul.get_aliases],
                        "summary": vul.summary,
                        "severities": [severity for severity in vul.severities.values()],
                        "references": [ref for ref in vul.references.values()],
                        "weaknesses": [
                            "CWE-" + str(weakness["cwe_id"]) for weakness in vul.weaknesses.values()
                        ],
                    }

            for items in [package_files, vul_files]:
                for filepath, data in items.items():
                    create_file(filepath, git_path, data)

            self.stdout.write(f"Successfully exported {ecosystem} data")


def create_file(filepath, git_path, data):
    """
    Check if the directories exist if it doesn't exist create a new one then Create the file
    ./aboutcode-vulnerabilities-12/34/VCID-1223-3434-34343/VCID-1223-3434-34343.yml
    ./aboutcode-packages-ed5/maven/org.apache.log4j/log4j-core/versions/vulnerabilities.yml
    ./aboutcode-packages-ed5/maven/org.apache.log4j/log4j-core/versions/1.2.3/vulnerabilities.yml
    """
    filepath = git_path.joinpath(filepath)
    dirname = os.path.dirname(filepath)
    os.makedirs(dirname, exist_ok=True)
    data = saneyaml.dump(data)
    with open(filepath, encoding="utf-8", mode="w") as f:
        f.write(data)


def get_purl_hash(purl: PackageURL, length: int = 3) -> str:
    """
    Return a short lower cased hash of a purl.
    https://github.com/nexB/purldb/pull/235/files#diff-a1fd023bd42d73f56019d540f38be711255403547add15108540d70f9948dd40R154
    """
    purl_bytes = str(purl).encode("utf-8")
    short_hash = sha512(purl_bytes).hexdigest()[:length]
    return short_hash.lower()
