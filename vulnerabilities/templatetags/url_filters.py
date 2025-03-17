from urllib.parse import quote

import packageurl
from django import template

register = template.Library()


@register.filter(name="url_quote")
def url_quote_filter(value):
    return quote(str(value))
