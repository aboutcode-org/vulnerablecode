#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import saneyaml
from django import template

register = template.Library()


@register.filter(name="to_yaml")
def to_yaml(value):
    """
    Convert a Python object (typically SSVC options) to a
    human-readable YAML string.
    """
    if not value:
        return ""
    try:
        return saneyaml.dump(value).strip()
    except Exception:
        return str(value)
    