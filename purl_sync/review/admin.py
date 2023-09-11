#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from django.contrib import admin

from review.models import Follow
from review.models import Note
from review.models import Person
from review.models import Purl
from review.models import RemotePerson
from review.models import RemoteService
from review.models import Repository
from review.models import Reputation
from review.models import Review
from review.models import Service
from review.models import Vulnerability

admin.site.register(Person)
admin.site.register(Service)

admin.site.register(Repository)
admin.site.register(Vulnerability)
admin.site.register(Purl)
admin.site.register(Note)
admin.site.register(Follow)
admin.site.register(Review)
admin.site.register(Reputation)

admin.site.register(RemoteService)
admin.site.register(RemotePerson)
