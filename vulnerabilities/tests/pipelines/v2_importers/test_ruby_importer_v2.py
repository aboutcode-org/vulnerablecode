#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

import pytest
from packageurl import PackageURL
from univers.version_range import GemVersionRange

from vulnerabilities.importer import AffectedPackageV2
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.pipelines.v2_importers.ruby_importer import RubyImporterPipeline
from vulnerabilities.pipelines.v2_importers.ruby_importer import get_affected_packages
from vulnerabilities.pipelines.v2_importers.ruby_importer import parse_ruby_advisory
from vulnerabilities.pipelines.v2_improvers.unfurl_version_range import UnfurlVersionRangePipeline
from vulnerabilities.pipes.advisory import insert_advisory_v2
from vulnerabilities.tests import util_tests
from vulnerabilities.tests.pipelines import TestLogger

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "ruby-v2"

TEST_CVE_FILES = [
    TEST_DATA / "gems/CVE-2020-5257.yml",
    TEST_DATA / "gems/CVE-2024-6531.yml",
    TEST_DATA / "rubies/CVE-2011-2686.yml",
    TEST_DATA / "rubies/CVE-2022-25857.yml",
]


@pytest.mark.django_db
@pytest.mark.parametrize("yml_file", TEST_CVE_FILES)
def test_ruby_advisories_per_file(yml_file):
    pipeline = RubyImporterPipeline()
    pipeline.vcs_response = Mock(dest_dir=TEST_DATA)

    with patch.object(Path, "rglob", return_value=[yml_file]):
        result = [adv.to_dict() for adv in pipeline.collect_advisories()]

    expected_file = yml_file.with_name(yml_file.stem + "-expected.json")
    util_tests.check_results_against_json(result, expected_file)


@pytest.mark.parametrize(
    "record,expected_affected,expected_fixed",
    [
        (
            {
                "unaffected_versions": ["< 4.2.0", ">= 5.0.0"],
                "patched_versions": [">= 4.2.7.1"],
            },
            "vers:gem/>=4.2.0|<5.0.0",
            ["vers:gem/>=4.2.7.1"],
        ),
        (
            {
                "unaffected_versions": ["~> 2.3.0", "~> 3.1.0", "~> 3.2.0"],
                "patched_versions": [">= 4.0.2"],
            },
            "vers:gem/<2.3.0|>=2.4|<3.1.0|>=3.3",
            ["vers:gem/>=4.0.2"],
        ),
        (
            {
                "unaffected_versions": ["< 4.2.3", "> 4.2.3"],
                "patched_versions": [">= 4.2.4"],
            },
            "vers:gem/4.2.3",
            ["vers:gem/>=4.2.4"],
        ),
        (
            {
                "unaffected_versions": ["< 2.0.0.beta1", "= 2.0.0-alpha"],
                "patched_versions": [">= 2.0.2"],
            },
            "vers:gem/>=2.0.0.beta1|!=2.0.0-alpha",
            ["vers:gem/>=2.0.2"],
        ),
        (
            {
                "unaffected_versions": ["< 1.0.12", "> 0.1.4"],
                "patched_versions": None,
            },
            None,
            [],
        ),
        (
            {
                "unaffected_versions": None,
                "patched_versions": [">= 1.0.0"],
            },
            None,
            ["vers:gem/>=1.0.0"],
        ),
        (
            {
                "unaffected_versions": ["< 1.0.0, > 2.0.0"],
                "patched_versions": [],
            },
            "vers:gem/*",
            [],
        ),
        (
            {
                "unaffected_versions": ["", "   "],
                "patched_versions": [],
            },
            None,
            [],
        ),
    ],
)
def test_get_affected_packages_combines_unaffected_versions(
    record, expected_affected, expected_fixed
):
    purl = PackageURL(type="gem", name="activerecord")
    affected_packages = get_affected_packages(record, purl)

    expected = []
    if expected_affected:
        expected.append(
            AffectedPackageV2(
                package=purl,
                affected_version_range=GemVersionRange.from_string(expected_affected),
                fixed_version_range=None,
            )
        )
    for fixed in expected_fixed:
        expected.append(
            AffectedPackageV2(
                package=purl,
                affected_version_range=None,
                fixed_version_range=GemVersionRange.from_string(fixed),
            )
        )

    assert affected_packages == expected


@pytest.mark.django_db
@patch("vulnerabilities.pipelines.v2_improvers.unfurl_version_range.get_purl_versions")
def test_ruby_multi_unaffected_versions_unfurl_does_not_mark_unaffected(mock_fetch):
    record = {
        "gem": "activerecord",
        "cve": "2016-6317",
        "title": "Unsafe Query Generation Risk in Active Record",
        "description": "Test description",
        "date": "2016-08-11",
        "unaffected_versions": ["< 4.2.0", ">= 5.0.0"],
        "patched_versions": [">= 4.2.7.1"],
    }
    advisory_url = (
        "https://github.com/rubysec/ruby-advisory-db/blob/master/"
        "gems/activerecord/CVE-2016-6317.yml"
    )
    advisory_data = parse_ruby_advisory(
        advisory_id="gems/CVE-2016-6317",
        record=record,
        schema_type="gems",
        advisory_url=advisory_url,
    )
    logger = TestLogger()
    insert_advisory_v2(
        advisory=advisory_data,
        pipeline_id=RubyImporterPipeline.pipeline_id,
        logger=logger.write,
        datasource_id=RubyImporterPipeline.datasource_id,
    )

    mock_fetch.return_value = {"4.1.16", "4.2.0", "4.2.7", "5.0.0", "7.1.3"}
    UnfurlVersionRangePipeline().execute()

    advisory = AdvisoryV2.objects.get(advisory_id="gems/CVE-2016-6317")
    affected_versions = set(
        advisory.impacted_packages.filter(affecting_vers__isnull=False)
        .first()
        .affecting_packages.values_list("version", flat=True)
    )
    assert affected_versions == {"4.2.0", "4.2.7"}
