from django import template
from packageurl import PackageURL

from purl_sync.settings import STATIC_URL

register = template.Library()


@register.filter
def get_purl_image(purl_webfinger):
    """
    Return the path of the image package
    """
    try:
        purl, _ = purl_webfinger.split("@")
        package_type = PackageURL.from_string(purl).type
        return "/" + STATIC_URL + "pictogram-gh-pages/" + package_type + "/" + package_type + ".png"
    except ValueError:
        return ""
