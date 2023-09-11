import json
from unittest import mock

import pytest

from review.activitypub import AP_CONTEXT, create_activity_obj
from review.models import Follow, Purl, Person, RemoteActor

from .test_models import person
from .test_models import purl
from .test_models import service
from ..utils import file_data
import requests_mock
#
# @mock.patch("fetchcode.package.get_response")
# def test_cargo_packages(mock_get):
#     side_effect = [file_data("tests/data/cargo_mock_data.json")]
#     purl = "pkg:cargo/rand"
#     expected_data = file_data("tests/data/cargo.json")
#     mock_get.side_effect = side_effect
#     packages = list(info(purl))
#     match_data(packages, expected_data)


# @mock.patch("fetchcode.package.get_response")
# def test_npm_packages(mock_get):
#     side_effect = [file_data("tests/data/npm_mock_data.json")]
#     purl = "pkg:npm/express"
#     expected_data = file_data("tests/data/npm.json")
#     mock_get.side_effect = side_effect
#     packages = list(info(purl))
#     match_data(packages, expected_data)
#

@pytest.fixture
def mock_requests_remote_purl():
    with requests_mock.Mocker() as m:
        m.get('https://127.0.0.2:8000/api/v0/purls/@pkg:maven/org.apache.logging',
              text=json.dumps({
                  "followers": "https://127.0.0.2:8000/api/v0/purls/@pkg:maven/org.apache.logging/followers/",
                  "id": "https://127.0.0.2:8000/api/v0/purls/@pkg:maven/org.apache.logging/",
                  "image": "https://127.0.0.2:8000/media/favicon16x16.png",
                  "inbox": "https://127.0.0.2:8000/api/v0/purls/@pkg:maven/org.apache.logging/inbox",
                  "name": "vcio",
                  "string": "pkg:maven/org.apache.logging",
                  "outbox": "https://127.0.0.2:8000/api/v0/purls/@pkg:maven/org.apache.logging/outbox",
                  "publicKey": {
                      "id": "https://127.0.0.2:8000/api/v0/purls/@pkg:maven/org.apache.logging/",
                      "owner": "https://127.0.0.2:8000/api/v0/users/@vcio",
                      "publicKeyPem": "BEGIN PUBLIC KEY...END PUBLIC " "KEY",
                  },
                  "type": "Purl",
              })

              )
        m.get('https://127.0.0.2:8000/.well-known/webfinger?resource=acct:pkg:maven/org.apache.logging@127.0.0.2:8000',
              text=json.dumps({
                  "subject": "acct:pkg:maven/org.apache.logging@127.0.0.2:8000",
                  "links": [
                      {
                          "rel": "https://webfinger.net/rel/profilepage",
                          "type": "text/html",
                          "href": "https://127.0.0.2:8000/purls/@pkg:maven/org.apache.logging"
                      },
                      {
                          "rel": "self",
                          "type": "application/activity+json",
                          "href": "https://127.0.0.2:8000/api/v0/purls/@pkg:maven/org.apache.logging"
                      }
                  ]
              }))
        yield m


@pytest.fixture
def mock_requests_remote_person():
    with requests_mock.Mocker() as m:
        m.get('https://127.0.0.2:8000/api/v0/users/@ziad',
              text=json.dumps({
                  "following": "https://127.0.0.2:8000/api/v0/users/@ziad/following/",
                  "id": "https://127.0.0.2:8000/api/v0/users/@ziad",
                  "image": "https://127.0.0.2:8000/media/favicon16x16.png",
                  "inbox": "https://127.0.0.2:8000/api/v0/users/@ziad/inbox",
                  "name": "ziad",
                  "outbox": "https://127.0.0.2:8000/api/v0/users/@ziad/outbox",
                  "publicKey": {
                      "id": "https://127.0.0.2:8000/api/v0/users/@ziad",
                      "owner": "https://127.0.0.2:8000/api/v0/users/@ziad",
                      "publicKeyPem": "BEGIN PUBLIC KEY...END PUBLIC " "KEY",
                  },
                  "summary": "Hello World",
                  "type": "Person",
              })

              )
        m.get('https://127.0.0.2:8000/.well-known/webfinger?resource=acct:ziad@127.0.0.2:8000',
              text=json.dumps({
                  "subject": "remoteziad@127.0.0.2:8000",
                  "links": [
                      {
                          "rel": "https://webfinger.net/rel/profilepage",
                          "type": "text/html",
                          "href": "https://127.0.0.2:8000/users/@ziad"
                      },
                      {
                          "rel": "self",
                          "type": "application/activity+json",
                          "href": "https://127.0.0.2:8000/api/v0/users/@ziad"
                      }
                  ]
              })
              )
        yield m


@pytest.mark.django_db
def test_remote_person_follow_purl(mock_requests_remote_person, purl):
    payload = json.dumps(
        {
            **AP_CONTEXT,
            "type": "Follow",
            "actor": f"https://127.0.0.2:8000/api/v0/users/@ziad",
            "object": {
                "type": "Purl",
                "id": "https://127.0.0.1:8000/api/v0/purls/@pkg:maven/org.apache.logging/",
            },
        }
    )

    activity = create_activity_obj(payload)
    activity_response = activity.handler()
    remote_person = RemoteActor.objects.get(url="https://127.0.0.2:8000/api/v0/users/@ziad", username="ziad").person

    assert Follow.objects.get(person=remote_person, purl=purl)
    assert Follow.objects.count() == 1


@pytest.mark.django_db
def test_person_follow_remote_purl(mock_requests_remote_purl, person):
    payload = json.dumps(
        {
            **AP_CONTEXT,
            "type": "Follow",
            "actor": f"https://127.0.0.1:8000/api/v0/users/@{person.user.username}",
            "object": {
                "type": "Purl",
                "id": "https://127.0.0.2:8000/api/v0/purls/@pkg:maven/org.apache.logging/",
            },
        }
    )

    activity = create_activity_obj(payload)
    follow_activity = activity.handler()
    remote_purl = RemoteActor.objects.get(url="https://127.0.0.2:8000/api/v0/purls/@pkg:maven/org.apache.logging/",
                                          username="vcio").purl

    assert Follow.objects.get(person=person, purl=remote_purl)
    assert Follow.objects.count() == 1
