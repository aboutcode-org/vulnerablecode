#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json
from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from vulnerabilities.pipelines.v2_importers.gentoo_importer import GentooImporterPipeline
from vulnerabilities.tests import util_tests

TEST_DATA = Path(__file__).parent.parent.parent / "test_data" / "gentoo_v2"

TEST_CVE_FILES = [
    TEST_DATA / "glsa-201709-09.xml",
    TEST_DATA / "glsa-202511-02.xml",
    TEST_DATA / "glsa-202512-01.xml",
]


@pytest.mark.django_db
@pytest.mark.parametrize("xml_file", TEST_CVE_FILES)
def test_gentoo_advisories_per_file(xml_file):
    pipeline = GentooImporterPipeline()
    pipeline.vcs_response = Mock(dest_dir=TEST_DATA)

    with patch.object(Path, "glob", return_value=[xml_file]):
        results = [adv.to_dict() for adv in pipeline.collect_advisories()]

    for adv in results:
        adv["affected_packages"].sort(key=lambda x: json.dumps(x, sort_keys=True))

    expected_file = xml_file.with_name(xml_file.stem + "-expected.json")
    util_tests.check_results_against_json(results, expected_file)


GLSA_TEMPLATE = """<?xml version="1.0" encoding="UTF-8"?>
<glsa id="209912-99">
  <synopsis>Probe advisory</synopsis>
  <references>
    <uri link="https://example.com/CVE-2099-9999">CVE-2099-9999</uri>
  </references>
  <affected>
    <package name="dev-libs/probe" auto="yes" arch="*">
      <vulnerable range="lt">{vulnerable}</vulnerable>
      <unaffected range="ge">9.9.9</unaffected>
    </package>
  </affected>
  <impact type="normal"/>
</glsa>
"""


def _process_glsa(tmp_path, vulnerable):
    xml_file = tmp_path / "glsa-probe.xml"
    xml_file.write_text(GLSA_TEMPLATE.format(vulnerable=vulnerable))
    pipeline = GentooImporterPipeline()
    return list(pipeline.process_file(xml_file))


@pytest.mark.django_db
def test_gentoo_invalid_version_does_not_build_empty_range(tmp_path):
    """An unparsable GLSA version must not produce an empty version range.

    A range built from no constraints serializes as "vers:ebuild/", which
    VersionRange.from_string rejects, so the affected package is dropped
    on round-trip. The entry is skipped instead, mirroring the
    apache_httpd importer fix for #2387.
    """
    advisories = _process_glsa(tmp_path, "1.0*")
    assert len(advisories) == 1
    affected_packages = advisories[0].affected_packages
    # Only the unaffected entry survives; the vulnerable entry is skipped.
    assert len(affected_packages) == 1
    assert affected_packages[0].affected_version_range is None
    assert str(affected_packages[0].fixed_version_range) == "vers:ebuild/>=9.9.9"


@pytest.mark.django_db
def test_gentoo_empty_version_element_does_not_crash(tmp_path):
    """An empty <vulnerable> element has no version text and must not crash
    the import: the entry is skipped, the unaffected entry is kept."""
    xml_file = tmp_path / "glsa-probe.xml"
    xml_file.write_text(
        GLSA_TEMPLATE.format(vulnerable="").replace(
            '<vulnerable range="lt"></vulnerable>', '<vulnerable range="lt"/>'
        )
    )
    pipeline = GentooImporterPipeline()
    advisories = list(pipeline.process_file(xml_file))
    assert len(advisories) == 1
    affected_packages = advisories[0].affected_packages
    assert len(affected_packages) == 1
    assert str(affected_packages[0].fixed_version_range) == "vers:ebuild/>=9.9.9"
