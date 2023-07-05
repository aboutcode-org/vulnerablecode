#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import logging
import re

from django.db import transaction
from django.db.models.query import QuerySet

from vulnerabilities.improver import Improver
from vulnerabilities.models import Commit
from vulnerabilities.models import VulnerabilityReference

logger = logging.getLogger(__name__)

"""
Improver that looks for commits related to a vulnerability
"""


class CommitRelationImprover(Improver):
    """
    Detect related commits to an advisory by applying a REGEX.
    """

    def __init__(self):
        # using cached insertion for memory efficiency
        self.insert_chunk_size = 500
        self.commit_instances = []

    @property
    def is_custom_improver(cls):
        return True

    @property
    def interesting_references(self) -> QuerySet:
        # Regex base coming from: https://github.com/secureIT-project/CVEfixes/
        # Below regex is the compatible form for Postgresql
        # For now, we are only interested in Bitbucket, Github and Gitlab sources
        # TODO: Add other sources such as Apache related sources, Linux kernel, etc.
        git_url = r"((https|http)://(bitbucket|github|gitlab)\.(org|com)/([^/]+)/([^/]*))/(commit|commits)/(\w+)#?"
        return VulnerabilityReference.objects.filter(
            url__iregex=git_url,
        )

    def __generate_instance(self):
        commit_pattern = r"(((?P<repo>(https|http):\/\/(bitbucket|github|gitlab)\.(org|com)\/(?P<owner>[^\/]+)\/(?P<project>[^\/]*))\/(commit|commits)\/(?P<hash>\w+)#?)+)"
        for ref in self.interesting_references:
            commit_groups = re.search(commit_pattern, ref.url)
            yield Commit(
                reference=ref,
                hash=commit_groups.group("hash"),
            )

    def __insert_bulk(self) -> None:
        if len(self.commit_instances) == 0:
            return

        with transaction.atomic():
            # Ignore_conflicts allows mass
            Commit.objects.bulk_create(self.commit_instances, ignore_conflicts=True)

            # Empty the cache buffer further inserts
            self.commit_instances.clear()

    def run(self) -> None:
        for i, commit in enumerate(self.__generate_instance()):
            self.commit_instances.append(commit)
            if len(self.commit_instances) >= self.insert_chunk_size:
                self.__insert_bulk()
        # Add remaining commits
        self.__insert_bulk()
