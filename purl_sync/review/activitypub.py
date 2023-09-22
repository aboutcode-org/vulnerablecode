#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import functools
import json
from dataclasses import asdict
from dataclasses import dataclass
from dataclasses import field
from typing import Literal
from typing import Optional
from urllib.parse import urlparse

from django.contrib.auth.models import User
from django.http import HttpResponseBadRequest
from django.http import HttpResponseForbidden
from django.http import JsonResponse
from django.urls import resolve
from git import Repo

from purl_sync.settings import GIT_PATH
from purl_sync.settings import PURL_SYNC_DOMAIN
from review.models import Follow
from review.models import Note
from review.models import Person
from review.models import Purl
from review.models import RemoteActor
from review.models import Repository
from review.models import Review
from review.models import Service
from review.models import Vulnerability
from review.signatures import PURL_SYNC_PRIVATE_KEY
from review.signatures import HttpSignature
from review.utils import fetch_actor
from review.utils import full_resolve
from review.utils import full_reverse
from review.utils import webfinger_actor

CONTENT_TYPE = "application/activity+json"
ACTOR_TYPES = ["Person", "Purl"]

ACTOR_PAGES = {"purl-profile": Purl, "user-profile": Person}

ACTIVITY_TYPES = ["Follow", "UnFollow", "Create", "Update", "Delete", "Sync"]

OBJECT_TYPES = {
    "Note": Note,
    "Review": Review,
    "Repository": Repository,
    "Vulnerability": Vulnerability,
}

AP_VALID_HEADERS = [
    'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
    "application/activity+json",
]

AP_CONTEXT = {
    "@context": ["https://www.w3.org/ns/activitystreams", "..........."],
}

AP_TARGET = {"cc": "https://www.w3.org/ns/activitystreams#Public"}

OBJ_Map = {
    "Note": "note-page",
    "Review": "review-page",
    "Repository": "repository-page",
    "Vulnerability": "vulnerability-page",
}

URL_MAPPER = {
    "user-ap-profile": "username",
    "purl-ap-profile": "purl_string",
    "review-page": "uuid",
    "repository-page": "uuid",
    "note-page": "uuid",
    "vulnerability-page": "uuid",
}


def check_and_r_ap_context(request):
    """
    check activitypub context request and return request without @context
    """
    if request.get("@context") == AP_CONTEXT["@context"]:
        request.pop("@context")
        return request
    else:
        return None


def add_ap_target(response):
    """
    Add target activitypub response
    """
    if response is not dict:
        raise KeyError("Invalid response")

    if not response.get("cc"):
        response.append(**AP_TARGET)

    return response


def has_valid_header(view):
    """
    check if the request header in the AP_VALID_HEADERS if yes return view else return HttpResponseForbidden
    """

    def wrapper(request, *args, **kwargs):
        content_type = request.headers.get("Content-Type")
        if content_type in AP_VALID_HEADERS:
            return view(request, *args, **kwargs)
        else:
            return

    return wrapper


@dataclass
class Activity:
    type: Literal["Follow", "UnFollow", "Create", "Update", "Delete", "Sync"]
    actor: Optional[str | dict]
    object: Optional[str | dict]
    to: list = field(default_factory=list)
    id: str = None

    def handler(self):
        ap_actor = ApActor(**self.actor) if isinstance(self.actor, dict) else ApActor(id=self.actor)
        ap_object = (
            ApObject(**self.object) if isinstance(self.object, dict) else ApObject(id=self.object)
        )
        return ACTIVITY_MAPPER[self.type](actor=ap_actor, object=ap_object, to=self.to).save()

    @classmethod
    def federated(cls, to, body, key_id):
        for target in to:
            target_domain = urlparse(target).netloc
            if target_domain != PURL_SYNC_DOMAIN:  # TODO Add a server whitelist if necessary
                HttpSignature.signed_request(target, body, PURL_SYNC_PRIVATE_KEY, key_id)


@dataclass
class ApActor:
    type: Literal["Person", "Purl"] = None
    id: str = None
    name: Optional[str] = None
    string: Optional[str] = None
    summary: Optional[str] = None
    inbox: str = None
    outbox: str = None
    following: Optional[str] = None
    followers: Optional[str] = None
    image: Optional[str] = None

    def get_by_type(self):
        if self.type in ACTOR_TYPES:
            if self.type == ACTOR_TYPES[0]:
                return Person.objects.get_or_none(user__username=self.name).to_ap()

            elif self.type == ACTOR_TYPES[1]:
                return Purl.objects.get_or_none(string=self.name).to_ap()

    def get(self):
        obj_id, page_name = full_resolve(self.id)
        if page_name == "purl-ap-profile":
            try:
                purl = Purl.objects.get(string=obj_id["purl_string"])
            except Purl.DoesNotExist:
                purl = None
            return purl

        elif page_name == "user-ap-profile":
            try:
                user = User.objects.get(username=obj_id["username"])
                if hasattr(user, "person"):
                    return user.person
                elif hasattr(user, "service"):
                    return user.service
            except User.DoesNotExist:
                user = None
        return None


@dataclass
class ApObject:
    type: Literal["Note", "Review", "Repository", "Vulnerability"] = None
    id: str = None
    content: str = None
    reply_to: str = None
    repository: str = None
    branch: str = None
    filename: str = None
    hash: str = None
    headline: str = None
    name: str = None
    url: str = None
    vulnerability: str = None
    published: str = None

    def get_object(self):
        if self.id:
            obj_id, page_name = full_resolve(self.id)
            identifier = URL_MAPPER[page_name]
            return OBJECT_TYPES[self.type].objects.get(id=obj_id[identifier])
        raise ValueError("Invalid object id")


@dataclass
class FollowActivity:
    type = "Follow"
    actor: ApActor
    object: ApActor
    to: list = field(default_factory=list)

    def save(self):
        actor = self.actor.get()
        parser = urlparse(self.actor.id)
        if not actor and parser.netloc != PURL_SYNC_DOMAIN:
            # remote person ( send a remote follow request if created and assume the request was accepted )
            resolver = resolve(parser.path)
            identity = URL_MAPPER[resolver.url_name]
            url = webfinger_actor(parser.netloc, resolver.kwargs[identity])
            actor_details = fetch_actor(url)
            remote_actor, created = RemoteActor.objects.get_or_create(
                username=actor_details["name"], url=actor_details["id"]
            )
            actor, created = Person.objects.get_or_create(remote_actor=remote_actor)
            Activity.federated(to=self.to, body=self.to_ap(), key_id=actor.key_id)
        # --------------------------------------------
        parser = urlparse(self.object.id)
        resolver = resolve(parser.path)
        obj_id, page_name = resolver.kwargs, resolver.url_name
        identity = URL_MAPPER[page_name]
        if parser.netloc == PURL_SYNC_DOMAIN:
            # local purl
            try:
                purl = Purl.objects.get(string=obj_id["purl_string"])
            except Purl.DoesNotExist:
                purl = None
        else:
            # remote purl
            url = webfinger_actor(parser.netloc, resolver.kwargs[identity])
            purl_details = fetch_actor(url)
            remote_actor, created = RemoteActor.objects.get_or_create(
                username=purl_details["name"], url=purl_details["id"]
            )
            purl, created = Purl.objects.get_or_create(
                remote_actor=remote_actor, string=purl_details["string"]
            )
            Activity.federated(to=self.to, body=self.to_ap(), key_id=actor.key_id)
        if purl and actor:
            Follow.objects.get_or_create(person=actor, purl=purl)
            return self.succeeded_ap_rs()

        return self.failed_ap_rs()

    def succeeded_ap_rs(self):
        """Response for successfully deleting the object"""
        return JsonResponse({"Location": "{self.object}"}, status=201)

    def failed_ap_rs(self):
        """Response for failure deleting the object"""
        return JsonResponse({"sd":"self.object"}, status=405)

    def to_ap(self):
        """Follow activity in activitypub format"""
        return {
            **AP_CONTEXT,
            "type": self.type,
            "actor": asdict(self.actor),
            "object": asdict(self.object),
            "to": self.to,
            **AP_TARGET,
        }


@dataclass
class CreateActivity:
    type = "Create"
    actor: ApActor
    object: ApObject
    to: list = field(default_factory=list)

    def save(self):
        new_obj, created = None, None
        actor = self.actor.get()
        if not actor:
            return self.failed_ap_rs()

        if isinstance(actor, Person):
            if self.object.type == "Note":
                reply_to = None
                if self.object.reply_to:
                    note_id = full_resolve(self.object.reply_to)
                    reply_to = Note.objects.get_or_none(id=note_id)

                new_obj, created = Note.objects.get_or_create(
                    acct=actor.acct,
                    content=self.object.content,
                    reply_to=reply_to,
                )
            elif self.object.type == "Review" and self.object.vulnerability:
                obj_id, page_name = full_resolve(self.object.vulnerability)
                vulnerability = Vulnerability.objects.get(id=obj_id["vulnerability_id"])

                new_obj, created = Review.objects.get_or_create(
                    headline=self.object.headline,
                    author=actor,
                    vulnerability=vulnerability,
                    data=self.object.content,
                )

        elif isinstance(actor, Purl):
            if self.object.type == "Note":
                reply_to = None
                if self.object.reply_to:
                    note_id = self.object.reply_to
                    reply_to = Note.objects.get_or_none(id=note_id)

                new_obj, created = Note.objects.get_or_create(
                    acct=actor.acct,
                    content=self.object.content,
                    reply_to=reply_to,
                )

        elif isinstance(actor, Service):
            if self.object.type == "Repository":
                new_obj, created = Repository.objects.get_or_create(
                    name=self.object.name, url=self.object.url, path=GIT_PATH, admin=actor
                )

        return self.succeeded_ap_rs(new_obj) if created else self.failed_ap_rs()

    def succeeded_ap_rs(self, new_obj):
        """Response for successfully deleting the object"""
        return JsonResponse(
            {"Location": full_reverse(OBJ_Map[self.object.type], new_obj.id)}, status=201
        )

    def failed_ap_rs(self):
        """Response for failure deleting the object"""
        return HttpResponseBadRequest("Invalid Create Activity request")

    def to_ap(self):
        """Request for creating object in activitypub format"""
        return {**AP_CONTEXT, "type": self.type, "actor": self.actor, "to": self.object}


@dataclass
class UpdateActivity:
    type = "Update"
    actor: ApActor
    object: ApObject
    to: list = field(default_factory=list)

    def save(self):
        updated_obj = None
        actor = self.actor.get()
        old_obj = self.object.get_object()
        if not actor:
            return self.failed_ap_rs()

        updated_param = {
            "Note": {"content": self.object.content},
            "Review": {"headline": self.object.headline, "data": self.object.content},
            "Repository": {"url": self.object.url, "name": self.object.name},
        }

        if (
            (isinstance(actor, Person) and self.object.type in ["Note", "Review"])
            or (isinstance(actor, Service) and self.object.type == "Repository")
            or (isinstance(actor, Purl) and self.object.type == "Note")
        ):
            for key, value in updated_param[self.object.type].items():
                if value:
                    setattr(old_obj, key, value)
            old_obj.save()

        return self.succeeded_ap_rs(old_obj.to_ap)

    def succeeded_ap_rs(self, update_obj):
        """Response for successfully deleting the object"""
        return JsonResponse(update_obj, status=200)

    def failed_ap_rs(self):
        """Response for failure deleting the object"""
        return HttpResponseBadRequest("Method Not Allowed", status=405)

    def to_ap(self):
        """Request for updating object in activitypub format"""
        return {**AP_CONTEXT, "type": self.type, "actor": self.actor, "to": self.object}


@dataclass
class DeleteActivity:
    actor: ApActor
    object: ApObject
    type = "Delete"
    to: list = field(default_factory=list)

    def save(self):
        actor = self.actor.get()
        if not actor:
            return self.failed_ap_rs()

        if (
            (type(actor) is Person and self.object.type in ["Note", "Review"])
            or (type(actor) is Purl and self.object.type in ["Note"])
            or (type(actor) is Service and self.object.type == ["Repository", "Purl"])
        ):
            instance = self.object.get_object()
            instance.delete()
            return self.succeeded_ap_rs()
        else:
            return self.failed_ap_rs()

    def ap_rq(self):
        """Request for deleting object in activitypub format"""
        return {**AP_CONTEXT, "type": self.type, "actor": self.actor, "to": self.object}

    def succeeded_ap_rs(self):
        """Response for successfully deleting the object"""
        return JsonResponse({"message": "The object has been deleted successfully"}, status=200)

    def failed_ap_rs(self):
        """Response for failure deleting the object"""
        return JsonResponse("Invalid object", status=404)


def create_activity_obj(data):
    """Convert json object to activity object"""
    payload = json.loads(data)
    payload_without_context = check_and_r_ap_context(payload)
    return Activity(**payload_without_context)


@dataclass
class UnFollowActivity:
    type = "UnFollow"
    actor: ApActor
    object: ApActor
    to: list = field(default_factory=list)

    def save(self):
        actor = self.actor.get()
        if not type(actor) is Person:
            return self.failed_ap_rs()
        else:
            obj_id, page_name = full_resolve(self.object.id)
            purl = Purl.objects.get(string=obj_id["purl_string"])
            follow_obj = Follow.objects.get(person_id=actor.id, purl=purl)
            follow_obj.delete()
            return self.succeeded_ap_rs()

    def succeeded_ap_rs(self):
        """Response for successfully deleting the object"""
        return JsonResponse({"Location": "{self.object}"}, status=201)

    def failed_ap_rs(self):
        """Response for failure deleting the object"""
        return JsonResponse({self.object}, status=405)

    def to_ap(self):
        """Follow activity in activitypub format"""
        return {
            **AP_CONTEXT,
            "type": self.type,
            "actor": self.actor,
            "to": self.object,
            **AP_TARGET,
        }


@dataclass
class SyncActivity:
    type = "Sync"
    actor: ApActor
    object: ApObject
    to: list = field(default_factory=list)

    def save(self):
        actor = self.actor.get()
        if not actor:
            return self.failed_ap_rs()
        repo = self.object.get_object().git_repo
        repo.remotes.origin.pull()
        return self.succeeded_ap_rs()

    def succeeded_ap_rs(self):
        """Response for successfully deleting the object"""
        return JsonResponse({}, status=201)

    def failed_ap_rs(self):
        """Response for failure deleting the object"""
        return JsonResponse({self.object}, status=405)


ACTIVITY_MAPPER = {
    "Create": CreateActivity,
    "Update": UpdateActivity,
    "Delete": DeleteActivity,
    "Follow": FollowActivity,
    "UnFollow": UnFollowActivity,
    "Sync": SyncActivity,
}
