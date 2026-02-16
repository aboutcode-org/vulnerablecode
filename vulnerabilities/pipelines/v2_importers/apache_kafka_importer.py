#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
from datetime import timezone
from traceback import format_exc as traceback_format_exc
from typing import Iterable

import requests
from bs4 import BeautifulSoup
from dateutil.parser import parse
from packageurl import PackageURL
from univers.version_range import ApacheVersionRange

from vulnerabilities.importer import AdvisoryDataV2
from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.importer import ReferenceV2
from vulnerabilities.models import AdvisoryReference
from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2
from vulnerabilities.pipes.apache_kafka import get_original_advisory
from vulnerabilities.pipes.apache_kafka import parse_range
from vulnerabilities.pipes.apache_kafka import parse_summary
from vulnerabilities.utils import build_description


class ApacheKafkaImporterPipeline(VulnerableCodeBaseImporterPipelineV2):
    """Import Apache Kafka Advisories"""

    pipeline_id = "apache_kafka_importer_v2"
    spdx_license_expression = "Apache-2.0"
    importer_name = "Apache Kafka Importer V2"

    license_url = "https://www.apache.org/licenses/"
    url = "https://kafka.apache.org/community/cve-list/"

    cve_without_affected_fixed_range = [
        "CVE-2022-23302",
        "CVE-2022-23305",
        "CVE-2022-23307",
        "CVE-2021-45046",
        "CVE-2021-44228",
        "CVE-2021-4104",
    ]

    precedence = 200

    @classmethod
    def steps(cls):
        return (
            cls.fetch,
            cls.collect_and_store_advisories,
        )

    def fetch(self):
        self.log(f"Fetch `{self.url}`")
        self.advisory_data = requests.get(self.url).text
        self.soup = BeautifulSoup(self.advisory_data, features="lxml")

    def advisories_count(self):
        return sum(1 for _ in self.soup.find(class_="td-content").find_all("table"))

    def collect_advisories(self) -> Iterable[AdvisoryDataV2]:
        for table in self.soup.find(class_="td-content").find_all("table"):
            yield self.to_advisory_data(table)

    def to_advisory_data(self, table) -> Iterable[AdvisoryDataV2]:
        affected_constraints = None
        fixed_constraints = None
        affected_packages = []
        references = []

        cve_h2 = table.find_previous("h2")
        refrence_a = cve_h2.find("a") or {}
        title = cve_h2.text
        ref_url = refrence_a.get("href")
        cve = cve_h2.get("id")

        raw_affected = table.find(text="Versions affected").find_next("p").text
        raw_fixed = table.find(text="Fixed versions").find_next("p").text
        raw_date = table.find(text="Issue announced").find_next("p").text
        date_published = parse(raw_date).replace(tzinfo=timezone.utc)

        description = parse_summary(cve_h2, table)
        original_advisory = get_original_advisory(cve_h2, table)

        if cve not in self.cve_without_affected_fixed_range:
            affected_constraints = parse_range(raw_affected)
            fixed_constraints = parse_range(raw_fixed)

        try:
            fixed_version_range = (
                ApacheVersionRange(constraints=fixed_constraints) if fixed_constraints else None
            )

            affected_version_range = (
                ApacheVersionRange(constraints=affected_constraints)
                if affected_constraints
                else None
            )
        except Exception as e:
            self.log(
                f"Failed to parse Kafka range for: {cve} with error {e!r}:\n{traceback_format_exc()}",
                level=logging.ERROR,
            )

        if affected_version_range or fixed_version_range:
            affected_packages.append(
                AffectedPackageV2(
                    package=PackageURL(type="apache", name="kafka"),
                    affected_version_range=affected_version_range,
                    fixed_version_range=fixed_version_range,
                )
            )

        references.append(
            ReferenceV2(
                reference_id=cve,
                reference_type=AdvisoryReference.OTHER,
                url=ref_url,
            )
        )

        return AdvisoryDataV2(
            advisory_id=cve,
            aliases=[],
            summary=build_description(summary=title, description=description),
            date_published=date_published,
            affected_packages=affected_packages,
            references=references,
            url=f"{self.url}#{cve}",
            original_advisory_text=original_advisory,
        )
