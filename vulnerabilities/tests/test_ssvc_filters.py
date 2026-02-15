#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from vulnerabilities.templatetags.ssvc_filters import to_yaml


def test_to_yaml_with_ssvc_options():
    options = [
        {"Exploitation": "active"},
        {"Automatable": "yes"},
        {"Technical Impact": "total"},
        {"Mission Prevalence": "essential"},
        {"Public Well-being Impact": "irreversible"},
        {"Mission & Well-being": "high"},
    ]
    result = to_yaml(options)
    assert "Exploitation: active" in result
    assert "Technical Impact: total" in result
    assert "Mission Prevalence: essential" in result
    assert "Public Well-being Impact: irreversible" in result


def test_to_yaml_with_empty_value():
    assert to_yaml(None) == ""
    assert to_yaml([]) == ""
    assert to_yaml("") == ""


def test_to_yaml_with_non_serializable_value():
    result = to_yaml("plain string")
    assert isinstance(result, str)
    