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
