#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import json
import os
from collections import defaultdict

import attr
from django.core.management.base import BaseCommand

from vulnerabilities.models import Vulnerability


@attr.attributes
class Purl2Cpe:
    vulnerablecode_id = attr.attrib(type=str)
    cves = attr.attrib(default=attr.Factory(list), type=list)
    purls = attr.attrib(default=attr.Factory(list), type=list, repr=False)
    cpes = attr.attrib(default=attr.Factory(list), type=list, repr=False)

    def to_dict(self):
        return attr.asdict(self)

    @classmethod
    def collect(cls, limit=0, verbose=False):
        """
        Yield Purl2Cpes collected from the current database.
        Apply a limit of provided
        """
        vulns = Vulnerability.objects.with_packages().with_cpes().distinct().all()
        if limit:
            vulns = vulns[:limit]

        for vuln in vulns:
            if verbose:
                print(f"Processing: {vuln.vulnerability_id}")
            yield cls(
                vulnerablecode_id=vuln.vulnerability_id,
                cves=vuln.get_related_cves(),
                purls=vuln.get_related_purls(),
                cpes=vuln.get_related_cpes(),
            )

    @classmethod
    def collect_by_years(cls, limit=0, verbose=False):
        """
        Return a mapping of {CVE year: [list of Purl2Cpes]}.
        Apply a limit of provided
        """
        by_years = defaultdict(list)
        for p2c in cls.collect(limit=limit, verbose=verbose):
            for cve in p2c.cves:
                try:
                    cve_year = cve.split("-")[1]
                    by_years[cve_year].append(p2c)
                except Exception as e:
                    raise Exception(cve) from e
        return by_years


class Command(BaseCommand):
    """
    Dump JSON mappings of CPEs and Package URLs by vulnerability.
    The process consists in these steps:

    - Iterate over all vulnerability with CPEs found in the VulnerableCode DB.
    - Collect their CVEs, CPEs and purls joined together through the CVEs.
    - Dump a list of Purl2Cpe grouped by year.
    """

    help = "Dump a mapping of CPEs to PURLs grouped by vulnerability."

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            default=0,
            help="Limit the number of processed vulnerability",
        )

        parser.add_argument("destination", help="Destination directory")

    def handle(self, *args, **options):
        limit = options["limit"]
        if isinstance(limit, str):
            limit = int(limit)

        destination = options["destination"]
        assert destination, "Missing required estination directory"
        destination = os.path.abspath(destination)
        os.makedirs(destination, exist_ok=True)

        by_years = Purl2Cpe.collect_by_years(limit=limit)

        for year, purl2cpes in by_years.items():
            purl2cpes = [y.to_dict() for y in purl2cpes]
            with open(os.path.join(destination, f"{year}.json"), "w") as out:
                json.dump(purl2cpes, out, indent=2)

        print(
            self.style.SUCCESS(f"Successfully dumped CPE to purl mappings in file://{destination}")
        )
