#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


import re

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


@register.filter
def humanize_minutes(duration):
    return humanize_time(seconds=duration * 60)


@register.simple_tag(takes_context=True)
def active_item(context, url_name):
    """Return is-active if navbar item is active."""
    request = context.get("request")
    if request and getattr(request, "resolver_match"):
        if request.resolver_match.url_name == url_name:
            return "is-active"
    return ""


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)


@register.simple_tag
def querystring(request, **kwargs):
    query = request.GET.copy()

    for key, value in kwargs.items():
        if value in [None, ""]:
            query.pop(key, None)
            continue
        query[key] = value

    return query.urlencode()


@register.filter
def normalize_links(value):
    """Normalize Markdown URLs."""
    if not value:
        return ""

    markdown_links = re.compile(r"\[([^\]]+)\]\((https?://[^\s)]+)\s*\)")
    return markdown_links.sub(r"\1 \2", value)


@register.filter
def humanize_interval(minutes):
    """Humanize pipeline run interval."""
    if minutes < 60:
        unit = "minute" if minutes == 1 else "minutes"
        return f"{minutes} {unit}"

    hours = minutes / 60
    value = int(hours) if hours.is_integer() else round(hours, 1)

    unit = "hour" if value == 1 else "hours"
    return f"{value} {unit}"
