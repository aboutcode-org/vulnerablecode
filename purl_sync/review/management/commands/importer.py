from dataclasses import dataclass
from pathlib import Path

import saneyaml
from django.core.management.base import BaseCommand
from django.core.management.base import CommandError

from review.models import Note
from review.models import Purl
from review.models import Repository
from review.models import Service
from review.models import Vulnerability
from review.utils import generate_webfinger


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
        for file in Path(self.repo_obj.path).glob("**/*.yaml"):
            with open(file) as f:
                yaml_data = saneyaml.load(f.read())
                if str(file.name).startswith("VCID"):
                    Vulnerability.objects.get_or_create(
                        repo=self.repo_obj,
                        filename=yaml_data.get("vulnerability_id"),
                    )
                else:
                    pacakge = yaml_data.get("pacakge")
                    if pacakge:
                        Purl.objects.get_or_create(string=pacakge, service=self.default_service)
                        pacakge_acct = generate_webfinger(pacakge)
                        old_notes = Note.objects.filter(acct=pacakge_acct)
                        for version in yaml_data.get("versions", []):
                            obj, created = Note.objects.get_or_create(acct=pacakge_acct, content=saneyaml.dump(version))
                            if not created:
                                old_notes = old_notes.exclude(obj)
                        old_notes.delete()
