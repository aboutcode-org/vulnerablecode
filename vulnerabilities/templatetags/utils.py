#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from django import template
import saneyaml

from aboutcode.pipeline import humanize_time

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


@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)


@register.filter
def yaml_dump(value):
    """Render structured data as YAML using saneyaml.dump."""
    if value is None:
        return ""
    try:
        return saneyaml.dump(value)
    except (TypeError, ValueError):
        return str(value)
