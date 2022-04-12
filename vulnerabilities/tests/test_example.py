import datetime
import os
from unittest.mock import patch

from django.test import TestCase
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import NginxVersionRange
from univers.versions import SemverVersion

from vulnerabilities import models
from vulnerabilities.import_runner import ImportRunner
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import ScoringSystem
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.improve_runner import ImproveRunner
from vulnerabilities.improvers.default import DefaultImprover
from vulnerabilities.tests.example_importer_improver import ExampleAliasImprover
from vulnerabilities.tests.example_importer_improver import ExampleImporter
from vulnerabilities.tests.example_importer_improver import parse_advisory_data


def mock_fetch_advisory_data():
    return [
        {
            "id": "CVE-2021-12341337",
            "summary": "Dummy advisory",
            "advisory_severity": "high",
            "vulnerable": "0.6.18-1.20.0",
            "fixed": "1.20.1",
            "reference": "http://example.com/cve-2021-1234",
            "published_on": "06-10-2021 UTC",
        }
    ]


def mock_fetch_additional_aliases(alias):
    alias_map = {
        "CVE-2021-12341337": ["ANONSEC-1337", "CERTDES-1337"],
    }
    return alias_map.get(alias)


@patch(
    "vulnerabilities.tests.example_importer_improver.fetch_advisory_data", mock_fetch_advisory_data
)
@patch(
    "vulnerabilities.tests.example_importer_improver.fetch_additional_aliases",
    mock_fetch_additional_aliases,
)
class TestExampleImporter(TestCase):
    def test_parse_advisory_data(self):
        raw_data = mock_fetch_advisory_data()[0]
        expected = AdvisoryData(
            aliases=["CVE-2021-12341337"],
            summary="Dummy advisory",
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(
                        type="example",
                        namespace=None,
                        name="dummy_package",
                        version=None,
                        qualifiers={},
                        subpath=None,
                    ),
                    affected_version_range=NginxVersionRange(
                        constraints=(
                            VersionConstraint(
                                comparator=">=", version=SemverVersion(string="0.6.18")
                            ),
                            VersionConstraint(
                                comparator="<=", version=SemverVersion(string="1.20.0")
                            ),
                        )
                    ),
                    fixed_version=SemverVersion(string="1.20.1"),
                )
            ],
            references=[
                Reference(
                    reference_id="",
                    url="http://example.com/cve-2021-1234",
                    severities=[
                        VulnerabilitySeverity(
                            system=ScoringSystem(
                                identifier="generic_textual",
                                name="Generic textual severity rating",
                                url="",
                                notes="Severity for unknown scoring systems. Contains generic textual values like High, Low etc",
                            ),
                            value="high",
                        )
                    ],
                )
            ],
            date_published=datetime.datetime(2021, 10, 6, 0, 0, tzinfo=datetime.timezone.utc),
        )
        actual = parse_advisory_data(raw_data)
        assert actual == expected

    def test_import_framework_using_example_importer(self):
        raw_datas = mock_fetch_advisory_data()
        ImportRunner(ExampleImporter).run()

        for raw_data in raw_datas:
            assert models.Advisory.objects.get(aliases__contains=raw_data["id"])

    def test_improve_framework_using_example_improver(self):
        ImportRunner(ExampleImporter).run()
        ImproveRunner(DefaultImprover).run()
        ImproveRunner(ExampleAliasImprover).run()
        raw_datas = mock_fetch_advisory_data()

        assert models.Package.objects.count() == 3
        assert models.PackageRelatedVulnerability.objects.filter(fix=True).count() == 1
        assert models.PackageRelatedVulnerability.objects.filter(fix=False).count() == 2
        assert models.VulnerabilitySeverity.objects.count() == 1
        assert models.VulnerabilityReference.objects.count() == 1
        for raw_data in raw_datas:
            assert models.Vulnerability.objects.get(summary=raw_data["summary"])
