#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest

from vulnerabilities.improve_runner import create_valid_vulnerability_reference


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
