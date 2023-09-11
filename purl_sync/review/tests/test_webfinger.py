import json

import pytest
from django.test import Client

from purl_sync.settings import DOMAIN

from ..utils import generate_webfinger
from .test_models import person
from .test_models import purl
from .test_models import service


@pytest.mark.django_db
def test_webfinger(person, service, purl):
    client = Client()
    person_acct = "acct:" + generate_webfinger(person.user.username)
    response_person = client.get(
        f"/.well-known/webfinger?resource={person_acct}",
    )

    service_acct = "acct:" + generate_webfinger(service.user.username)
    response_service = client.get(
        f"/.well-known/webfinger?resource={service_acct}",
    )

    purl_acct = "acct:" + generate_webfinger(purl.string)
    response_purl = client.get(
        f"/.well-known/webfinger?resource={purl_acct}",
    )

    assert json.loads(response_person.content) == {
        "subject": person_acct,
        "links": [
            {
                "rel": "https://webfinger.net/rel/profile-page",
                "type": "text/html",
                "href": f"https://{DOMAIN}/users/@{person.user.username}",
            },
            {
                "rel": "self",
                "type": "application/activity+json",
                "href": f"https://{DOMAIN}/api/v0/users/@{person.user.username}",
            },
        ],
    }

    assert json.loads(response_service.content) == {
        "subject": service_acct,
        "links": [
            {
                "rel": "https://webfinger.net/rel/profile-page",
                "type": "text/html",
                "href": f"https://{DOMAIN}/users/@{service.user.username}",
            },
            {
                "rel": "self",
                "type": "application/activity+json",
                "href": f"https://{DOMAIN}/api/v0/users/@{service.user.username}",
            },
        ],
    }

    assert json.loads(response_purl.content) == {
        "subject": purl_acct,
        "links": [
            {
                "rel": "https://webfinger.net/rel/profile-page",
                "type": "text/html",
                "href": f"https://{DOMAIN}/purls/@{ purl.string }",
            },
            {
                "rel": "self",
                "type": "application/activity+json",
                "href": f"https://{DOMAIN}/api/v0/purls/@{ purl.string }",
            },
        ],
    }
