#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json

import pytest

from review.activitypub import AP_CONTEXT
from review.activitypub import create_activity_obj
from review.models import Follow
from review.models import Note
from review.models import Repository
from review.models import Review

from .test_models import follow
from .test_models import mute_post_save_signal
from .test_models import note
from .test_models import person
from .test_models import purl
from .test_models import repo
from .test_models import service
from .test_models import vulnerability


@pytest.mark.django_db
def test_person_create_note(person):
    payload = json.dumps(
        {
            **AP_CONTEXT,
            "type": "Create",
            "actor": f"https://127.0.0.1:8000/api/v0/users/@{person.user.username}",
            "object": {
                "type": "Note",
                "content": "we should fix this purl",
            },
        }
    )

    activity = create_activity_obj(payload)
    create_activity = activity.handler()
    assert Note.objects.count() == 1
    note = Note.objects.get(acct=person.acct, content="we should fix this purl")
    assert json.loads(create_activity.content) == {
        "Location": f"https://127.0.0.1:8000/notes/{note.id}"
    }
    assert create_activity.status_code == 201


@pytest.mark.django_db
def test_person_create_review(person, vulnerability, repo):
    payload = json.dumps(
        {
            **AP_CONTEXT,
            "type": "Create",
            "actor": f"https://127.0.0.1:8000/api/v0/users/@ziad",
            "object": {
                "type": "Review",
                "headline": "review vulnerablecode-data VCID-0000-0000-0000",
                "repository": f"https://127.0.0.1:8000/repository/{repo.id}/",
                "vulnerability": f"https://127.0.0.1:8000/vulnerability/{vulnerability.id}/",
                "content": "diff text",
            },
        }
    )

    activity = create_activity_obj(payload)
    create_activity = activity.handler()
    assert Review.objects.count() == 1
    review = Review.objects.get(
        headline="review vulnerablecode-data VCID-0000-0000-0000",
        author=person,
        vulnerability=vulnerability,
        data="diff text",
        status=0,
    )
    assert json.loads(create_activity.content) == {
        "Location": f"https://127.0.0.1:8000/reviews/{review.id}/"
    }
    assert create_activity.status_code == 201


@pytest.mark.django_db
def test_purl_create_note(purl, service):
    payload = json.dumps(
        {
            **AP_CONTEXT,
            "type": "Create",
            "actor": f"https://127.0.0.1:8000/api/v0/purls/@{purl.string}/",
            "object": {
                "type": "Note",
                "content": "we should fix this purl",
            },
        }
    )
    activity = create_activity_obj(payload)
    create_activity = activity.handler()
    note = Note.objects.get(acct=purl.acct, content="we should fix this purl")
    assert json.loads(create_activity.content) == {
        "Location": f"https://127.0.0.1:8000/notes/{note.id}"
    }
    assert create_activity.status_code == 201


@pytest.mark.django_db
def test_service_create_repo(service):
    payload = json.dumps(
        {
            **AP_CONTEXT,
            "type": "Create",
            "actor": f"https://127.0.0.1:8000/api/v0/users/@{service.user.username}",
            "object": {
                "type": "Repository",
                "name": "vulnerablecode",
                "url": "https://github.com/nexB/vulnerablecode-data",
            },
        }
    )
    activity = create_activity_obj(payload)
    create_activity = activity.handler()
    assert Repository.objects.count() == 1
    repo = Repository.objects.get(
        name="vulnerablecode", url="https://github.com/nexB/vulnerablecode-data"
    )
    assert json.loads(create_activity.content) == {
        "Location": f"https://127.0.0.1:8000/repository/{repo.id}/"
    }
    assert create_activity.status_code == 201


@pytest.mark.django_db
def test_person_follow_purl(person, purl):
    payload = json.dumps(
        {
            **AP_CONTEXT,
            "type": "Follow",
            "actor": f"https://127.0.0.1:8000/api/v0/users/@{person.user.username}",
            "object": {
                "type": "Purl",
                "id": f"https://127.0.0.1:8000/api/v0/purls/@pkg:maven/org.apache.logging/",
            },
        }
    )

    activity = create_activity_obj(payload)
    follow_activity = activity.handler()
    assert Follow.objects.get(person=person, purl=purl)
    assert Follow.objects.count() == 1


@pytest.mark.django_db
def test_person_delete_note(person, note):
    payload = json.dumps(
        {
            **AP_CONTEXT,
            "type": "Delete",
            "actor": f"https://127.0.0.1:8000/api/v0/users/@{person.user.username}",
            "object": {
                "type": "Note",
                "id": f"https://127.0.0.1:8000/notes/{note.id}",
            },
        }
    )

    activity = create_activity_obj(payload)
    delete_activity = activity.handler()
    assert Note.objects.count() == 0
    assert json.loads(delete_activity.content) == {
        "message": "The object has been deleted successfully"
    }
    assert delete_activity.status_code == 200


@pytest.mark.django_db
def test_person_delete_note(person, note):
    payload = json.dumps(
        {
            **AP_CONTEXT,
            "type": "Delete",
            "actor": f"https://127.0.0.1:8000/api/v0/users/@{person.user.username}",
            "object": {
                "type": "Note",
                "id": f"https://127.0.0.1:8000/notes/{note.id}",
            },
        }
    )

    activity = create_activity_obj(payload)
    delete_activity = activity.handler()
    assert Note.objects.count() == 0


@pytest.mark.django_db
def test_person_update_note(person, note):
    payload = json.dumps(
        {
            **AP_CONTEXT,
            "type": "Update",
            "actor": f"https://127.0.0.1:8000/api/v0/users/@{person.user.username}",
            "object": {
                "id": f"https://127.0.0.1:8000/notes/{note.id}",
                "type": "Note",
                "content": "Hello World!",
            },
        }
    )

    activity = create_activity_obj(payload)
    update_activity = activity.handler()
    assert Note.objects.count() == 1
    note = Note.objects.get(id=note.id)
    assert note.content == "Hello World!"
    assert json.loads(update_activity.content) == note.to_ap
    assert update_activity.status_code == 200


@pytest.mark.django_db
def test_person_unfollow_purl(person, purl, follow):
    payload = json.dumps(
        {
            **AP_CONTEXT,
            "type": "UnFollow",
            "actor": f"https://127.0.0.1:8000/api/v0/users/@{person.user.username}",
            "object": {
                "type": "Purl",
                "id": f"https://127.0.0.1:8000/api/v0/purls/@pkg:maven/org.apache.logging/",
            },
        }
    )

    activity = create_activity_obj(payload)
    follow_activity = activity.handler()
    assert Follow.objects.count() == 0


# @pytest.mark.django_db
# def test_person_sync_repo(service, repo):
#     payload = json.dumps(
#         {
#             **AP_CONTEXT,
#             "type": "Sync",
#             "actor": f"https://127.0.0.1:8000/users/@{service.user.username}",
#             "object": {
#                 "type": "Repository",
#                 "id": f"https://127.0.0.1:8000/repository/{repo.id}/",
#             },
#         }
#     )
#
#     activity = create_activity_obj(payload)
#     sync_activity = activity.handler()
