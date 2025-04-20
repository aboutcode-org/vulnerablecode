#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import datetime
from unittest import TestCase

import pytz
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import compute_content_id


class TestComputeContentId(TestCase):
    def setUp(self):
        self.maxDiff = None
        self.base_advisory = AdvisoryData(
            summary="Test summary",
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(
                        type="npm",
                        name="package1",
                        qualifiers={},
                    ),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.0.0|<2.0.0"),
                )
            ],
            references=[
                Reference(
                    url="https://example.com/vuln1",
                    reference_id="GHSA-1234-5678-9012",
                    severities=[
                        VulnerabilitySeverity(
                            system=SCORING_SYSTEMS["cvssv3.1"],
                            value="7.5",
                        )
                    ],
                )
            ],
            date_published=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
        )

    def test_same_content_different_order_same_id(self):
        """
        Test that advisories with same content but different ordering have same content ID
        """
        advisory1 = self.base_advisory

        # Same content but different order of references and affected packages
        advisory2 = AdvisoryData(
            summary="Test summary",
            affected_packages=list(reversed(self.base_advisory.affected_packages)),
            references=list(reversed(self.base_advisory.references)),
            date_published=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
        )

        assert compute_content_id(advisory1) == compute_content_id(advisory2)

    def test_different_metadata_same_content_same_id(self):
        """
        Test that advisories with same content but different metadata have same content ID
        when include_metadata=False
        """
        advisory1 = self.base_advisory

        advisory2 = AdvisoryData(
            summary=self.base_advisory.summary,
            affected_packages=self.base_advisory.affected_packages,
            references=self.base_advisory.references,
            date_published=self.base_advisory.date_published,
            url=self.base_advisory.url,
        )

        assert compute_content_id(advisory1) == compute_content_id(advisory2)

    def test_different_summary_different_id(self):
        """
        Test that advisories with different summaries have different content IDs
        """
        advisory1 = self.base_advisory

        advisory2 = AdvisoryData(
            summary="Different summary",
            affected_packages=self.base_advisory.affected_packages,
            references=self.base_advisory.references,
            date_published=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
        )

        self.assertNotEqual(
            compute_content_id(advisory1),
            compute_content_id(advisory2),
        )

    def test_different_affected_packages_different_id(self):
        """
        Test that advisories with different affected packages have different content IDs
        """
        advisory1 = self.base_advisory

        advisory2 = AdvisoryData(
            summary="Test summary",
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(
                        type="npm",
                        name="different-package",
                        qualifiers={},
                    ),
                    affected_version_range=VersionRange.from_string("vers:npm/>=1.0.0|<2.0.0"),
                )
            ],
            references=self.base_advisory.references,
            date_published=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
        )

        self.assertNotEqual(
            compute_content_id(advisory1),
            compute_content_id(advisory2),
        )

    def test_different_references_different_id(self):
        """
        Test that advisories with different references have different content IDs
        """
        advisory1 = self.base_advisory

        advisory2 = AdvisoryData(
            summary="Test summary",
            affected_packages=self.base_advisory.affected_packages,
            references=[
                Reference(
                    url="https://example.com/different-vuln",
                    reference_id="GHSA-9999-9999-9999",
                    severities=[
                        VulnerabilitySeverity(
                            system=SCORING_SYSTEMS["cvssv3.1"],
                            value="8.5",
                        )
                    ],
                )
            ],
            date_published=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
        )

        self.assertNotEqual(
            compute_content_id(advisory1),
            compute_content_id(advisory2),
        )

    def test_different_weaknesses_different_id(self):
        """
        Test that advisories with different weaknesses have different content IDs
        """
        advisory1 = AdvisoryData(
            summary="Test summary",
            affected_packages=self.base_advisory.affected_packages,
            references=self.base_advisory.references,
            weaknesses=[1, 2, 3],
            date_published=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
        )

        advisory2 = AdvisoryData(
            summary="Test summary",
            affected_packages=self.base_advisory.affected_packages,
            references=self.base_advisory.references,
            weaknesses=[4, 5, 6],
            date_published=datetime.datetime(2024, 1, 1, tzinfo=pytz.UTC),
        )

        self.assertNotEqual(
            compute_content_id(advisory1),
            compute_content_id(advisory2),
        )

    def test_empty_fields_same_id(self):
        """
        Test that advisories with empty optional fields still generate same content ID
        """
        advisory1 = AdvisoryData(
            summary="",
            affected_packages=self.base_advisory.affected_packages,
            references=self.base_advisory.references,
            date_published=None,
        )

        advisory2 = AdvisoryData(
            summary="",
            affected_packages=self.base_advisory.affected_packages,
            references=self.base_advisory.references,
            date_published=None,
        )

        self.assertEqual(
            compute_content_id(advisory1),
            compute_content_id(advisory2),
        )
