import requests
from vulnerablecode.settings import VULNERABLECODE_USER_AGENT


def get(url, **kwargs):
    headers = kwargs.pop("headers", {})
    headers.setdefault("User-Agent", VULNERABLECODE_USER_AGENT)
    return requests.get(url, headers=headers, **kwargs)
