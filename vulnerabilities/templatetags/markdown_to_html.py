import markdown
from django import template

register = template.Library()


@register.filter(name="markdown_to_html")
def markdown_to_html(text):
    return markdown.markdown(text)
