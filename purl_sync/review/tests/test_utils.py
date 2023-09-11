#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import json
import uuid

import pytest

from review.activitypub import AP_CONTEXT
from review.activitypub import Activity
from review.activitypub import create_activity_obj
from review.utils import check_purl_actor
from review.utils import full_resolve
from review.utils import full_reverse


@pytest.mark.parametrize(
    "payload,expected",
    [
        (
            {
                **AP_CONTEXT,
                "type": "Create",
                "actor": "https://dustycloud.org/chris/",
                "object": "https://rhiaro.co.uk/2016/05/minimal-activitypub",
            },
            Activity(
                type="Create",
                actor="https://dustycloud.org/chris/",
                object="https://rhiaro.co.uk/2016/05/minimal-activitypub",
            ),
        ),
        (
            {
                **AP_CONTEXT,
                "id": "https://example.com/api/activity/2",
                "type": "Update",
                "actor": "https://example.com/chris/",
                "object": {
                    "type": "Note",
                    "id": "https://example.com/note/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
                    "actor": "https://example.com/user/@user1",
                    "content": "we should fix purl",
                },
            },
            Activity(
                id="https://example.com/api/activity/2",
                type="Update",
                actor="https://example.com/chris/",
                object={
                    "type": "Note",
                    "id": "https://example.com/note/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
                    "actor": "https://example.com/user/@user1",
                    "content": "we should fix purl",
                },
            ),
        ),
    ],
)
def test_load_activity(payload, expected):
    json_payload = json.dumps(payload)
    assert create_activity_obj(json_payload) == expected


def test_full_reverse():
    assert (
        full_reverse("note-page", "7e676ad1-995d-405c-a829-cb39813c74e5")
        == "https://127.0.0.1/notes/7e676ad1-995d-405c-a829-cb39813c74e5"
    )


def test_full_resolve():
    assert full_resolve(f"https://127.0.0.1:8000/notes/7e676ad1-995d-405c-a829-cb39813c74e5") == (
        {"uuid": uuid.UUID("7e676ad1-995d-405c-a829-cb39813c74e5")},
        "note-page",
    )


def test_check_purl_actor():
    assert check_purl_actor("pkg:maven/org.apache.logging")
