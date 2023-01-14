#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest

from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import Reference
from vulnerabilities.improver import MAX_CONFIDENCE
from vulnerabilities.improver import Inference
from vulnerabilities.improver import PackageURL


def test_empty_inference_raises_exception():
    with pytest.raises(AssertionError):
        Inference()


def test_inference_to_dict_method_with_vulnerability_id():
    inference = Inference(vulnerability_id="vulcoid-1337")
    expected = {
        "vulnerability_id": "vulcoid-1337",
        "aliases": [],
        "confidence": MAX_CONFIDENCE,
        "summary": "",
        "affected_purls": [],
        "fixed_purl": None,
        "references": [],
    }
    assert expected == inference.to_dict()


def test_inference_to_dict_method_with_purls():
    purl = PackageURL(type="dummy", namespace="rick", name="jalebi", version="1")
    inference = Inference(affected_purls=[purl], fixed_purl=purl)
    expected = {
        "vulnerability_id": None,
        "aliases": [],
        "confidence": MAX_CONFIDENCE,
        "summary": "",
        "affected_purls": [purl.to_dict()],
        "fixed_purl": purl.to_dict(),
        "references": [],
    }
    assert expected == inference.to_dict()


def test_inference_to_dict_method_with_versionless_purls_raises_exception():
    versionless_purl = PackageURL(type="dummy", namespace="rick", name="gulabjamun")
    with pytest.raises(AssertionError):
        Inference(affected_purls=[versionless_purl], fixed_purl=versionless_purl)


def test_inference_from_advisory_data():
    aliases = ["lalmohan", "gulabjamun"]
    summary = "really tasty sweets"
    references = [Reference(url="http://localhost")]
    advisory_data = AdvisoryData(aliases=aliases, summary=summary, references=references)
    fixed_purl = PackageURL(name="mithai", version="1", type="sweets")
    inference = Inference.from_advisory_data(
        advisory_data=advisory_data, fixed_purl=fixed_purl, confidence=MAX_CONFIDENCE
    )
    assert inference == Inference(
        aliases=aliases, summary=summary, references=references, fixed_purl=fixed_purl
    )
