#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest
from django.contrib.auth.models import User
from django.db.models.signals import post_save

from ..models import Follow
from ..models import Note
from ..models import Person
from ..models import Purl
from ..models import Repository
from ..models import Review
from ..models import Service
from ..models import Vulnerability


@pytest.fixture
def service(db):
    user = User.objects.create(
        username="vcio",
        email="vcio@nexb.com",
        password="complex-password",
    )
    return Service.objects.create(
        user=user,
    )


@pytest.fixture
def purl(db, service):
    return Purl.objects.create(
        string="pkg:maven/org.apache.logging",
        service=service,
    )


@pytest.fixture
def person(db):
    user1 = User.objects.create(
        username="ziad",
        email="ziad@nexb.com",
        password="complex-password",
    )
    return Person.objects.create(user=user1, summary="Hello World", public_key="PUBLIC_KEY")


def test_person(person):
    assert person.user.username == "ziad"
    assert person.user.email == "ziad@nexb.com"
    assert person.summary == "Hello World"
    assert person.public_key == "PUBLIC_KEY"


def test_purl(purl, service):
    assert purl.service == service
    assert purl.string == "pkg:maven/org.apache.logging"
    assert Purl.objects.count() == 1


@pytest.fixture
def repo(db, service, mute_post_save_signal):
    return Repository.objects.create(
        name="vulnerablecode_data",
        url="https://github.com/nexB/fake-repo",
        path="./review/test_data/test_git_repo",
        admin=service,
    )


@pytest.fixture
def vulnerability(db, repo):
    return Vulnerability.objects.create(
        repo=repo,
        filename="VCID-rf6e-vjeu-aaae.json",
        commit_id="49d8c5fd4bea9488186a832b13ebdc83484f1b6a",
    )


@pytest.fixture
def review(db, vulnerability, person):
    return Review.objects.create(
        headline="Review title 1",
        author=person,
        vulnerability=vulnerability,
        data="text diff",
    )


@pytest.fixture
def note(db):
    return Note.objects.create(
        acct="ziad@vcio",
        content="Comment #1",
    )


@pytest.fixture
def follow(db, purl, person):
    return Follow.objects.create(purl=purl, person=person)


def test_follow(follow, purl, person):
    assert follow.purl.string == purl.string
    assert follow.person.user == person.user


def test_review(review, person, vulnerability):
    assert review.headline == "Review title 1"
    assert review.author == person
    assert review.vulnerability == vulnerability
    assert review.data == "text diff"
    assert review.status == 0


def test_vulnerability(vulnerability, repo):
    assert vulnerability.repo == repo
    assert vulnerability.filename == "VCID-rf6e-vjeu-aaae.json"
    assert vulnerability.commit_id == "49d8c5fd4bea9488186a832b13ebdc83484f1b6a"


@pytest.fixture(autouse=True)
def mute_post_save_signal(request):
    """
    copied from https://www.cameronmaske.com/muting-django-signals-with-a-pytest-fixture/
    """
    post_save.receivers = []
