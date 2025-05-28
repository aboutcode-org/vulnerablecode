#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from django import template
from django.utils.safestring import mark_safe

register = template.Library()


@register.filter(is_safe=True)
def cvss_printer(selected_vector, vector_values):
    """highlight the selected vector value and return a list of paragraphs"""
    p_list = []
    selected_vector = selected_vector.lower()
    for vector_value in vector_values.split(","):
        if selected_vector == vector_value:
            p_list.append(f"<p class='has-text-black-bis mb-2'>{selected_vector}</p>")
        else:
            p_list.append(f"<p class='has-text-grey mb-2'>{vector_value}</p>")
    return mark_safe("".join(p_list))
