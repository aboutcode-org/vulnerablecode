#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import pytest

from ..management.commands.importer import Importer
from ..models import Note
from ..models import Purl
from ..models import Vulnerability
from .test_models import mute_post_save_signal
from .test_models import repo
from .test_models import service


@pytest.mark.django_db
@pytest.mark.skip("")
def test_importer(service, repo, mute_post_save_signal):
    importer = Importer(repo, service)
    importer.run()

    assert Note.objects.count() > 0
    assert Vulnerability.objects.count() > 0
    assert Purl.objects.count() > 0
