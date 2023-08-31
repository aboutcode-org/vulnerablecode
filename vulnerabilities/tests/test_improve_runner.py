#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from collections import Counter

import pytest
from django.utils import timezone
from packageurl import PackageURL
from pytest_django.asserts import assertQuerysetEqual

from vulnerabilities.importer import Reference
from vulnerabilities.improve_runner import create_valid_vulnerability_reference
from vulnerabilities.improve_runner import get_or_create_vulnerability_and_aliases
from vulnerabilities.improve_runner import process_inferences
from vulnerabilities.improver import Improver
from vulnerabilities.improver import Inference
from vulnerabilities.models import Advisory
from vulnerabilities.models import Alias
from vulnerabilities.models import Package
from vulnerabilities.models import PackageRelatedVulnerability
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilityRelatedReference
from vulnerabilities.models import VulnerabilitySeverity


@pytest.mark.django_db
def test_create_valid_vulnerability_reference_basic():
    result = create_valid_vulnerability_reference(
        reference_id="cpe:2.3:a:microsoft:windows_10:10.0.17134:*:*:*:*:*:*:*",
        url="https://foo.bar",
    )
    assert result


@pytest.mark.django_db
def test_create_valid_vulnerability_reference_raise_exception_on_empty_url():
    result = create_valid_vulnerability_reference(
        reference_id="cpe:2.3:a:microsoft:windows_10:10.0.17134:*:*:*:*:*:*:*",
        url="",
    )
    assert not result


@pytest.mark.django_db
def test_create_valid_vulnerability_reference_accepts_long_references():
    result = create_valid_vulnerability_reference(
        reference_id="*" * 200,
        url="https://foo.bar",
    )
    assert result


@pytest.mark.django_db
def test_get_or_create_vulnerability_and_aliases_with_new_vulnerability_and_new_aliases():
    alias_names = ["TAYLOR-1337", "SWIFT-1337"]
    summary = "Melodious vulnerability"
    vulnerability = get_or_create_vulnerability_and_aliases(
        alias_names=alias_names, summary=summary
    )
    assert vulnerability
    alias_names_in_db = vulnerability.get_aliases.values_list("alias", flat=True)
    assert Counter(alias_names_in_db) == Counter(alias_names)


@pytest.mark.django_db
def test_get_or_create_vulnerability_and_aliases_with_different_vulnerability_and_existing_aliases():
    existing_vulnerability = Vulnerability(vulnerability_id="VCID-Existing")
    existing_vulnerability.save()
    existing_aliases = []
    existing_alias_names = ["ALIAS-1", "ALIAS-2"]
    for alias in existing_alias_names:
        existing_aliases.append(Alias(alias=alias, vulnerability=existing_vulnerability))
    Alias.objects.bulk_create(existing_aliases)

    different_vulnerability = Vulnerability(vulnerability_id="VCID-New")
    different_vulnerability.save()
    assert not get_or_create_vulnerability_and_aliases(
        alias_names=existing_alias_names, vulnerability_id=different_vulnerability.vulnerability_id
    )


@pytest.mark.django_db
def test_get_or_create_vulnerability_and_aliases_with_existing_vulnerability_and_new_aliases():
    existing_vulnerability = Vulnerability(vulnerability_id="VCID-Existing")
    existing_vulnerability.save()

    existing_alias_names = ["ALIAS-1", "ALIAS-2"]
    vulnerability = get_or_create_vulnerability_and_aliases(
        vulnerability_id="VCID-Existing", alias_names=existing_alias_names
    )
    assert existing_vulnerability == vulnerability

    alias_names_in_db = vulnerability.get_aliases.values_list("alias", flat=True)
    assert Counter(alias_names_in_db) == Counter(existing_alias_names)


@pytest.mark.django_db
def test_get_or_create_vulnerability_and_aliases_with_existing_vulnerability_and_existing_aliases():
    existing_vulnerability = Vulnerability(vulnerability_id="VCID-Existing")
    existing_vulnerability.save()

    existing_aliases = []
    existing_alias_names = ["ALIAS-1", "ALIAS-2"]
    for alias in existing_alias_names:
        existing_aliases.append(Alias(alias=alias, vulnerability=existing_vulnerability))
    Alias.objects.bulk_create(existing_aliases)

    vulnerability = get_or_create_vulnerability_and_aliases(
        vulnerability_id="VCID-Existing", alias_names=existing_alias_names
    )
    assert existing_vulnerability == vulnerability

    alias_names_in_db = vulnerability.get_aliases.values_list("alias", flat=True)
    assert Counter(alias_names_in_db) == Counter(existing_alias_names)


@pytest.mark.django_db
def test_get_or_create_vulnerability_and_aliases_with_existing_vulnerability_and_existing_and_new_aliases():
    existing_vulnerability = Vulnerability(vulnerability_id="VCID-Existing")
    existing_vulnerability.save()

    existing_aliases = []
    existing_alias_names = ["ALIAS-1", "ALIAS-2"]
    for alias in existing_alias_names:
        existing_aliases.append(Alias(alias=alias, vulnerability=existing_vulnerability))
    Alias.objects.bulk_create(existing_aliases)

    new_alias_names = ["ALIAS-3", "ALIAS-4"]
    alias_names = existing_alias_names + new_alias_names
    vulnerability = get_or_create_vulnerability_and_aliases(
        vulnerability_id="VCID-Existing", alias_names=alias_names
    )
    assert existing_vulnerability == vulnerability

    alias_names_in_db = vulnerability.get_aliases.values_list("alias", flat=True)
    assert Counter(alias_names_in_db) == Counter(alias_names)


DUMMY_ADVISORY = Advisory(summary="dummy", created_by="tests", date_collected=timezone.now())


@pytest.mark.django_db
def test_process_inferences_with_no_inference():
    assert not process_inferences(
        inferences=[], advisory=DUMMY_ADVISORY, improver_name="test_improver"
    )


@pytest.mark.django_db
def test_process_inferences_with_unknown_but_specified_vulnerability():
    inference = Inference(vulnerability_id="VCID-Does-Not-Exist-In-DB", aliases=["MATRIX-Neo"])
    assert not process_inferences(
        inferences=[inference], advisory=DUMMY_ADVISORY, improver_name="test_improver"
    )


INFERENCES = [
    Inference(
        aliases=["CVE-1", "CVE-2"],
        summary="One upon a time, in a package far far away",
        affected_purls=[
            PackageURL(type="character", namespace="star-wars", name="anakin", version="1")
        ],
        fixed_purl=PackageURL(
            type="character", namespace="star-wars", name="darth-vader", version="1"
        ),
        references=[Reference(reference_id="imperial-vessel-1", url="https://m47r1x.github.io")],
    )
]


def get_objects_in_all_tables_used_by_process_inferences():
    return {
        "vulnerabilities": list(Vulnerability.objects.all()),
        "aliases": list(Alias.objects.all()),
        "references": list(VulnerabilityReference.objects.all()),
        "advisories": list(Advisory.objects.all()),
        "packages": list(Package.objects.all()),
        "references": list(VulnerabilityReference.objects.all()),
        "severity": list(VulnerabilitySeverity.objects.all()),
    }


@pytest.mark.django_db
def test_process_inferences_idempotency():
    process_inferences(INFERENCES, DUMMY_ADVISORY, improver_name="test_improver")
    all_objects = get_objects_in_all_tables_used_by_process_inferences()
    process_inferences(INFERENCES, DUMMY_ADVISORY, improver_name="test_improver")
    process_inferences(INFERENCES, DUMMY_ADVISORY, improver_name="test_improver")
    assert all_objects == get_objects_in_all_tables_used_by_process_inferences()


@pytest.mark.django_db
def test_process_inference_idempotency_with_different_improver_names():
    process_inferences(INFERENCES, DUMMY_ADVISORY, improver_name="test_improver_one")
    all_objects = get_objects_in_all_tables_used_by_process_inferences()
    process_inferences(INFERENCES, DUMMY_ADVISORY, improver_name="test_improver_two")
    process_inferences(INFERENCES, DUMMY_ADVISORY, improver_name="test_improver_three")
    assert all_objects == get_objects_in_all_tables_used_by_process_inferences()
