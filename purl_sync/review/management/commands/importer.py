import json
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
        parser.add_argument("import", nargs="*")
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
        git_repo = self.repo_obj.git_repo_obj
        for commit in git_repo.commit().tree.traverse():
            file = Path(commit.abspath)
            if file.is_file():
                with open(commit.abspath) as f:
                    yaml_data = saneyaml.load(f.read())
                    if str(file.name).startswith("VCID") and str(file.name).endswith(".yaml"):
                        Vulnerability.objects.get_or_create(
                            repo=self.repo_obj, filename=yaml_data.get("vulnerability_id")
                        )
                    elif str(file.name).endswith(".yaml"):
                        self.register_pkg(yaml_data)

    def register_pkg(self, data):
        pacakge = data.get("pacakge")
        if pacakge:
            Purl.objects.get_or_create(string=pacakge, service=self.default_service)
            for version in data.get("versions", []):
                acct = generate_webfinger(pacakge)
                Note.objects.get_or_create(acct=acct, content=saneyaml.dump(version))
