#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging
from dataclasses import dataclass
from pathlib import Path

import saneyaml
from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from review.activitypub import Activity
from review.activitypub import CreateActivity
from review.models import Note
from review.models import Purl
from review.models import Repository
from review.models import Service
from review.models import Vulnerability
from review.utils import generate_webfinger

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Import a git repository files"

    def add_arguments(self, parser):
        parser.add_argument(
            "--all",
            action="store_true",
            help="Import all the file from a git repository",
        )

    def handle(self, *args, **options):
        if options["all"]:
            for repo_obj in Repository.objects.all():
                Importer(repo_obj, repo_obj.admin).run()
                self.stdout.write(
                    self.style.SUCCESS('Successfully Imported git repo "%s"' % repo_obj.path)
                )


@dataclass
class Importer:
    repo_obj: Repository
    default_service: Service

    def run(self):
        for file in Path(self.repo_obj.path).glob("**/*.yml"):
            with open(file) as f:
                yaml_data = saneyaml.load(f.read())
                if str(file.name).startswith("VCID"):
                    Vulnerability.objects.get_or_create(
                        repo=self.repo_obj,
                        filename=yaml_data.get("vulnerability_id"),
                    )
                else:
                    package = yaml_data.get("package")
                    if package:
                        purl, purl_created = Purl.objects.get_or_create(
                            string=package, service=self.default_service
                        )
                        pacakge_acct = generate_webfinger(package)
                        if purl_created:
                            for version in yaml_data.get("versions", []):
                                note, note_created = Note.objects.get_or_create(
                                    acct=pacakge_acct, content=saneyaml.dump(version)
                                )
                                if note_created:
                                    purl.notes.add(note)
                        else:
                            old_notes_ids = list(purl.notes.all().values_list("id", flat=True))
                            for version in yaml_data.get("versions", []):
                                note, note_created = Note.objects.get_or_create(
                                    acct=pacakge_acct, content=saneyaml.dump(version)
                                )

                                if not note_created:
                                    old_notes_ids.remove(note.id)
                                else:
                                    purl.notes.add(note)
                                    create_activity = CreateActivity(
                                        actor=purl.to_ap, object=note.to_ap
                                    )
                                    Activity.federated(
                                        to=purl.followers_inboxes,
                                        body=create_activity.to_ap(),
                                        key_id=purl.key_id,
                                    )
                            purl.notes.filter(id__in=old_notes_ids).delete()
                            Note.objects.filter(id__in=old_notes_ids).delete()

                    else:
                        logger.error(f"Invalid package {file.name}")
