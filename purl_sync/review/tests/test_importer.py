#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import pytest

from ..importer import Importer
from ..models import Note
from ..models import Purl
from ..models import Vulnerability
from .test_models import mute_post_save_signal
from .test_models import repo
from .test_models import service


@pytest.mark.skip(reason="Need a real git repo to test the importer")
@pytest.mark.django_db
def test_simple_importer(service, repo, mute_post_save_signal):
    # just add all packages and vulnerabilities
    repo.path = "/home/ziad/vul-sample"
    importer = Importer(repo, service)
    importer.run()

    assert Note.objects.count() > 1
    assert Vulnerability.objects.count() > 1
    assert Purl.objects.count() > 1
    assert repo.last_imported_commit

    note_n = Note.objects.count()
    vul_n = Vulnerability.objects.count()
    purl_n = Purl.objects.count()
    last_imported_commit = repo.last_imported_commit

    # Run importer again without add any new data
    importer = Importer(repo, service)
    importer.run()

    assert note_n == Note.objects.count()
    assert vul_n == Vulnerability.objects.count()
    assert purl_n == Purl.objects.count()
    assert last_imported_commit == repo.last_imported_commit

    # Edit last_imported_commit
    repo.last_imported_commit = "3445628953e52c1edea926a7c0f3985f8995b3c9"
    repo.save()
    importer = Importer(repo, service)
    importer.run()


# @pytest.mark.django_db
# def test_complex_importer(service, repo, mute_post_save_signal):
#     repo.last_imported_commit = '3445628953e52c1edea926a7c0f3985f8995b3c9'
#     importer = Importer(repo, service)
#     importer.run()
#
#     assert Note.objects.count() == 2
#     assert Vulnerability.objects.count() == 2
#     assert Purl.objects.count() == 1
#
#     purl = Purl.objects.get(string="pkg:alpine/bash")
#     assert purl.notes.count() == 2
#
#     repo.path = "./review/tests/test_data/test_git_repo_v2"
#     repo.save()
#
#     importer = Importer(repo, service)
#     importer.run()
#
#     assert Note.objects.count() == 3
#     assert Vulnerability.objects.count() == 2
#     assert Purl.objects.count() == 1
