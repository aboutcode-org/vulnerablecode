#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import dataclasses
import json
import os
import uuid
from urllib.parse import urlparse

import requests
from django.contrib.auth.models import User
from django.urls import resolve
from django.urls import reverse
from git.repo.base import Repo
from packageurl import PackageURL

from purl_sync.settings import DOMAIN




def parse_webfinger(subject):
    """
    get the username and host from webfinger acct:user@host
    >>> parse_webfinger("acct:ziadhany@example.com")
    ('ziadhany', 'example.com')
    >>> parse_webfinger("acct:")
    ('', '')
    >>> parse_webfinger("ziadhany@example.com")
    ('ziadhany', 'example.com')
    """
    if subject.startswith("acct"):
        acct = subject[5:]
        result = acct.split("@")
        user_part, host = "", ""
        if len(result) == 2:
            user_part, host = result
        return user_part, host
    else:
        return tuple(subject.split("@"))


def generate_webfinger(username):
    return username + "@" + DOMAIN


def clone_git_repo(repo_path, repo_name, repo_url):
    """
    Create Git repository in ${repo_path}/${repo_name}.git and git pull origin branch
    """
    repo = Repo.clone_from(repo_url, os.path.join(repo_path, repo_name))
    return repo


def full_reverse(page_name, *args, **kwargs):
    web_page = reverse(page_name, args=args, kwargs=kwargs)
    return f'{"https://"}{DOMAIN}{web_page}'


def full_resolve(full_path):
    parser = urlparse(full_path)
    resolver = resolve(parser.path)
    return resolver.kwargs, resolver.url_name


def check_purl_actor(purl_string):
    """
    Purl actor is a purl without a version
    """
    purl = PackageURL.from_string(purl_string)
    if not (purl.version or purl.qualifiers or purl.subpath):
        return True
    return False


def ap_collection(objects):
    """
    accept the result of the query like filter and Add all objects in activitypub collection format
    https://www.w3.org/TR/activitystreams-vocabulary/#dfn-orderedcollection
    """
    return {
        "type": "OrderedCollection",
        "totalItems": objects.count(),
        "orderedItems": [obj.to_ap for obj in objects.all()],
    }


def fetch_actor(acct):
    user, domain = parse_webfinger(acct)
    url = f"https://{domain}/.well-known/webfinger?resource={acct}"
    headers = {"User-Agent": ""}  # TODO
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to fetch the actor {response.status_code} {response.content}")
