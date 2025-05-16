#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from aboutcode.pipeline import humanize_time
from django import template

register = template.Library()


@register.filter
def strip(value):
    if isinstance(value, str):
        return value.strip()
    return value


@register.filter
def humanize_duration(duration):
    return humanize_time(seconds=duration)


@register.simple_tag(takes_context=True)
def active_item(context, url_name):
    """Return is-active if navbar item is active."""
    request = context.get("request")
    if request and getattr(request, "resolver_match"):
        if request.resolver_match.url_name == url_name:
            return "is-active"
    return ""
