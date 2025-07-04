#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime

import pytest
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils import timezone
from packageurl import PackageURL
from univers.version_range import VersionRange

from vulnerabilities import models
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryReference
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryWeakness
from vulnerabilities.pipes.advisory import get_or_create_advisory_aliases
from vulnerabilities.pipes.advisory import get_or_create_advisory_references
from vulnerabilities.pipes.advisory import get_or_create_advisory_severities
from vulnerabilities.pipes.advisory import get_or_create_advisory_weaknesses
from vulnerabilities.pipes.advisory import get_or_create_aliases
from vulnerabilities.pipes.advisory import import_advisory
from vulnerabilities.utils import compute_content_id


class TestPipeAdvisory(TestCase):
    def setUp(self):
        self.advisory_data1 = AdvisoryData(
            summary="vulnerability description here",
            affected_packages=[
                AffectedPackage(
                    package=PackageURL(type="pypi", name="dummy"),
                    affected_version_range=VersionRange.from_string("vers:pypi/>=1.0.0|<=2.0.0"),
                )
            ],
            references=[Reference(url="https://example.com/with/more/info/CVE-2020-13371337")],
            date_published=timezone.now(),
            url="https://test.com",
        )

    def get_advisory1(self, created_by="test_pipeline"):
        from vulnerabilities.pipes.advisory import insert_advisory

        return insert_advisory(
            advisory=self.advisory_data1,
            pipeline_id=created_by,
        )

    def get_all_vulnerability_relationships_objects(self):
        return {
            "vulnerabilities": list(models.Vulnerability.objects.all()),
            "aliases": list(models.Alias.objects.all()),
            "references": list(models.VulnerabilityReference.objects.all()),
            "advisories": list(models.Advisory.objects.all()),
            "packages": list(models.Package.objects.all()),
            "references": list(models.VulnerabilityReference.objects.all()),
            "severity": list(models.VulnerabilitySeverity.objects.all()),
        }

    def test_vulnerability_pipes_importer_import_advisory(self):
        advisory1 = self.get_advisory1(created_by="test_importer_pipeline")
        import_advisory(advisory=advisory1, pipeline_id="test_importer_pipeline")
        all_vulnerability_relation_objects = self.get_all_vulnerability_relationships_objects()
        import_advisory(advisory=advisory1, pipeline_id="test_importer_pipeline")
        assert (
            all_vulnerability_relation_objects == self.get_all_vulnerability_relationships_objects()
        )

    def test_vulnerability_pipes_importer_import_advisory_different_pipelines(self):
        advisory1 = self.get_advisory1(created_by="test_importer_pipeline")
        import_advisory(advisory=advisory1, pipeline_id="test_importer1_pipeline")
        all_vulnerability_relation_objects = self.get_all_vulnerability_relationships_objects()
        import_advisory(advisory=advisory1, pipeline_id="test_importer2_pipeline")
        assert (
            all_vulnerability_relation_objects == self.get_all_vulnerability_relationships_objects()
        )

    def test_vulnerability_pipes_get_or_create_aliases(self):
        aliases = ["CVE-TEST-123", "CVE-TEST-124"]
        result_aliases_qs = get_or_create_aliases(aliases=aliases)
        result_aliases = [i.alias for i in result_aliases_qs]
        assert 2 == result_aliases_qs.count()
        assert "CVE-TEST-123" in result_aliases
        assert "CVE-TEST-124" in result_aliases

    def test_advisory_insert_without_url(self):
        with self.assertRaises(ValidationError):
            date = datetime.now()
            models.Advisory.objects.create(
                unique_content_id=compute_content_id(advisory_data=self.advisory_data1),
                summary=self.advisory_data1.summary,
                affected_packages=[pkg.to_dict() for pkg in self.advisory_data1.affected_packages],
                references=[ref.to_dict() for ref in self.advisory_data1.references],
                date_imported=date,
                date_collected=date,
                created_by="test_pipeline",
            )

    def test_advisory_insert_without_content_id(self):
        with self.assertRaises(ValidationError):
            date = datetime.now()
            models.Advisory.objects.create(
                url=self.advisory_data1.url,
                summary=self.advisory_data1.summary,
                affected_packages=[pkg.to_dict() for pkg in self.advisory_data1.affected_packages],
                references=[ref.to_dict() for ref in self.advisory_data1.references],
                date_imported=date,
                date_collected=date,
                created_by="test_pipeline",
            )

    def test_advisory_insert_no_duplicate_content_id(self):
        date = datetime.now()
        models.Advisory.objects.create(
            unique_content_id=compute_content_id(advisory_data=self.advisory_data1),
            url=self.advisory_data1.url,
            summary=self.advisory_data1.summary,
            affected_packages=[pkg.to_dict() for pkg in self.advisory_data1.affected_packages],
            references=[ref.to_dict() for ref in self.advisory_data1.references],
            date_imported=date,
            date_collected=date,
            created_by="test_pipeline",
        )

        with self.assertRaises(ValidationError):
            models.Advisory.objects.create(
                unique_content_id=compute_content_id(advisory_data=self.advisory_data1),
                url=self.advisory_data1.url,
                summary=self.advisory_data1.summary,
                affected_packages=[pkg.to_dict() for pkg in self.advisory_data1.affected_packages],
                references=[ref.to_dict() for ref in self.advisory_data1.references],
                date_imported=date,
                date_collected=date,
                created_by="test_pipeline",
            )


@pytest.fixture
def advisory_aliases():
    return ["CVE-2021-12345", "GHSA-xyz"]


@pytest.fixture
def advisory_references():
    return [
        Reference(reference_id="REF-1", url="https://example.com/advisory/1"),
        Reference(reference_id="REF-2", url="https://example.com/advisory/2"),
        Reference(reference_id="", url="https://example.com/advisory/3"),
        Reference(url="https://example.com/advisory/4"),
    ]


@pytest.fixture
def advisory_severities():
    class Severity:
        def __init__(self, system, value, scoring_elements, published_at=None, url=None):
            self.system = system
            self.value = value
            self.scoring_elements = scoring_elements
            self.published_at = published_at
            self.url = url

    class System:
        def __init__(self, identifier):
            self.identifier = identifier

    return [
        Severity(
            System("CVSSv3"),
            "7.5",
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            timezone.now(),
            "https://cvss.example.com",
        ),
    ]


@pytest.fixture
def advisory_weaknesses():
    return [79, 89]


@pytest.mark.django_db
def test_get_or_create_advisory_aliases(advisory_aliases):
    aliases = get_or_create_advisory_aliases(advisory_aliases)
    assert len(aliases) == len(advisory_aliases)
    for alias_obj in aliases:
        assert isinstance(alias_obj, AdvisoryAlias)
        assert alias_obj.alias in advisory_aliases


@pytest.mark.django_db
def test_get_or_create_advisory_references(advisory_references):
    refs = get_or_create_advisory_references(advisory_references)
    assert len(refs) == len(advisory_references)
    for ref in refs:
        assert isinstance(ref, AdvisoryReference)
        assert ref.url in [r.url for r in advisory_references]


@pytest.mark.django_db
def test_get_or_create_advisory_severities(advisory_severities):
    sevs = get_or_create_advisory_severities(advisory_severities)
    assert len(sevs) == len(advisory_severities)
    for sev in sevs:
        assert isinstance(sev, AdvisorySeverity)
        assert sev.scoring_system == advisory_severities[0].system.identifier
        assert sev.value == advisory_severities[0].value


@pytest.mark.django_db
def test_get_or_create_advisory_weaknesses(advisory_weaknesses):
    weaknesses = get_or_create_advisory_weaknesses(advisory_weaknesses)
    assert len(weaknesses) == len(advisory_weaknesses)
    for w in weaknesses:
        assert isinstance(w, AdvisoryWeakness)
        assert w.cwe_id in advisory_weaknesses
