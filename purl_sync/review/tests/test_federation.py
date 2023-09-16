import json
from unittest import mock

import pytest

from review.activitypub import AP_CONTEXT
from review.activitypub import create_activity_obj
from review.models import Follow
from review.models import RemoteActor

from ..utils import file_data
from .test_models import person
from .test_models import purl
from .test_models import service


@pytest.mark.django_db
@mock.patch("requests.get")
def test_remote_person_follow_purl(mock_get, purl):
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
    mock_request_remote_person_webfinger = mock.Mock(status_code=200)
    mock_request_remote_person_webfinger.json.return_value = file_data(
        "review/tests/test_data/mock_request_remote_person_webfinger.json"
    )

    mock_request_remote_person = mock.Mock(status_code=200)
    mock_request_remote_person.json.return_value = file_data(
        "review/tests/test_data/mock_request_remote_person.json"
    )
    mock_get.side_effect = [mock_request_remote_person_webfinger, mock_request_remote_person]

    activity = create_activity_obj(payload)
    activity_response = activity.handler()
    remote_person = RemoteActor.objects.get(
        url="https://127.0.0.2:8000/api/v0/users/@ziad", username="ziad"
    ).person

    assert Follow.objects.get(person=remote_person, purl=purl)
    assert Follow.objects.count() == 1


@pytest.mark.django_db
@mock.patch("requests.get")
def test_person_follow_remote_purl(mock_get, person):
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
    mock_request_remote_purl_webfinger = mock.Mock(status_code=200)
    mock_request_remote_purl_webfinger.json.return_value = file_data(
        "review/tests/test_data/mock_request_remote_purl_webfinger.json"
    )

    mock_request_remote_purl = mock.Mock(status_code=200)
    mock_request_remote_purl.json.return_value = file_data(
        "review/tests/test_data/mock_request_remote_purl.json"
    )
    mock_get.side_effect = [mock_request_remote_purl_webfinger, mock_request_remote_purl]

    follow_activity = activity.handler()
    remote_purl = RemoteActor.objects.get(
        url="https://127.0.0.2:8000/api/v0/purls/@pkg:maven/org.apache.logging/", username="vcio"
    ).purl

    assert Follow.objects.get(person=person, purl=remote_purl)
    assert Follow.objects.count() == 1
