#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime
from datetime import timezone
from typing import Iterable

from django.db.models.query import QuerySet
from packageurl import PackageURL
from univers.version_range import NginxVersionRange
from univers.versions import SemverVersion

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Importer
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory
from vulnerabilities.severity_systems import SCORING_SYSTEMS


class ExampleImporter(Importer):
    spdx_license_expression = "BSD-2-Clause"

    def advisory_data(self) -> Iterable[AdvisoryData]:
        raw_data = fetch_advisory_data()
        for data in raw_data:
            yield parse_advisory_data(data)


def fetch_advisory_data():
    return [
        {
            "id": "CVE-2021-230171337",
            "summary": "1-byte memory overwrite in resolver",
            "advisory_severity": "medium",
            "vulnerable": "0.6.18-1.20.0",
            "fixed": "1.20.1",
            "reference": "http://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html",
            "published_on": "14-02-2021 UTC",
        },
        {
            "id": "CVE-2021-12341337",
            "summary": "Dummy advisory",
            "advisory_severity": "high",
            "vulnerable": "0.6.18-1.20.0",
            "fixed": "1.20.1",
            "reference": "http://example.com/cve-2021-1234",
            "published_on": "06-10-2021 UTC",
        },
    ]


def parse_advisory_data(raw_data) -> AdvisoryData:
    """
    Return AdvisoryData build from a mapping of ``raw_data`` example advisory.
    """
    purl = PackageURL(type="example", name="dummy_package")
    affected_version_range = NginxVersionRange.from_native(raw_data["vulnerable"])
    fixed_version = SemverVersion(raw_data["fixed"])
    affected_package = AffectedPackage(
        package=purl, affected_version_range=affected_version_range, fixed_version=fixed_version
    )
    severity = VulnerabilitySeverity(
        system=SCORING_SYSTEMS["generic_textual"], value=raw_data["advisory_severity"]
    )
    references = [Reference(url=raw_data["reference"], severities=[severity])]
    # The original format is "06-10-2021 UTC" and we convert this a
    date_published = datetime.strptime(raw_data["published_on"], "%d-%m-%Y %Z").replace(
        tzinfo=timezone.utc
    )

    return AdvisoryData(
        aliases=[raw_data["id"]],
        summary=raw_data["summary"],
        affected_packages=[affected_package],
        references=references,
        date_published=date_published,
    )


class ExampleAliasImprover(Improver):
    @property
    def interesting_advisories(self) -> QuerySet:
        return Advisory.objects.filter(created_by=ExampleImporter.qualified_name)

    def get_inferences(self, advisory_data) -> Iterable[Inference]:
        for alias in advisory_data.aliases:
            new_aliases = fetch_additional_aliases(alias)
            aliases = new_aliases + [alias]
            yield Inference(aliases=aliases, confidence=MAX_CONFIDENCE)


def fetch_additional_aliases(alias):
    alias_map = {
        "CVE-2021-230171337": ["PYSEC-1337", "CERTIN-1337"],
        "CVE-2021-12341337": ["ANONSEC-1337", "CERTDES-1337"],
    }
    return alias_map.get(alias)
