import logging
import os.path
from dataclasses import dataclass
from itertools import zip_longest

import saneyaml

from review.activitypub import Activity
from review.activitypub import CreateActivity
from review.activitypub import DeleteActivity
from review.activitypub import UpdateActivity
from review.models import Note
from review.models import Purl
from review.models import Repository
from review.models import Service
from review.models import Vulnerability

logger = logging.getLogger(__name__)


@dataclass
class Importer:
    repo_obj: Repository
    default_service: Service

    def run(self):
        repo = self.repo_obj.git_repo_obj
        latest_commit_hash = repo.heads.master.commit.hexsha
        latest_commit = repo.commit(latest_commit_hash)
        if self.repo_obj.last_imported_commit:
            last_imported_commit = repo.commit(self.repo_obj.last_imported_commit)
            diffs = last_imported_commit.diff(latest_commit)
        else:
            last_imported_commit = None
            # Diff between empty trees and last_imported_commit
            diffs = latest_commit.diff("4b825dc642cb6eb9a060e54bf8d69288fbee4904", R=True)

        if repo.heads.master.commit.hexsha == self.repo_obj.last_imported_commit:
            logger.error("Nothing to import!")
            return

        for diff in diffs:
            if not diff.a_path.endswith(".yml"):
                continue

            if diff.a_path.startswith("."):
                continue

            yaml_data_a_blob = (
                saneyaml.load(diff.a_blob.data_stream.read()) if diff.a_blob else None
            )
            yaml_data_b_blob = (
                saneyaml.load(diff.b_blob.data_stream.read()) if diff.b_blob else None
            )

            if os.path.split(diff.a_path)[1].startswith("VCID") or os.path.split(diff.b_path)[
                1
            ].startswith("VCID"):
                vul_handler(diff.change_type, self.repo_obj, yaml_data_a_blob, yaml_data_b_blob)
                continue

            pkg_handler(diff.change_type, self.default_service, yaml_data_a_blob, yaml_data_b_blob)
        self.repo_obj.last_imported_commit = latest_commit_hash
        self.repo_obj.save()
        logger.info("The Importer run successfully")


def vul_handler(change_type, repo_obj, yaml_data_a_blob, yaml_data_b_blob):
    if change_type == "A":  # A for added paths
        Vulnerability.objects.get_or_create(
            repo=repo_obj,
            filename=yaml_data_b_blob.get("vulnerability_id"),
        )
    elif change_type in ["M", "R"]:  # R for renamed paths , M for paths with modified data
        vul = Vulnerability.objects.get(
            repo=repo_obj,
            filename=yaml_data_a_blob.get("vulnerability_id"),
        )
        vul.filename = yaml_data_b_blob.get("vulnerability_id")
        vul.save()
    elif change_type == "D":  # D for deleted paths
        vul = Vulnerability.objects.filter(
            repo=repo_obj,
            filename=yaml_data_a_blob.get("vulnerability_id"),
        )
        vul.delete()
    else:
        logger.error(f"Invalid Vulnerability File")


def pkg_handler(change_type, default_service, yaml_data_a_blob, yaml_data_b_blob):
    if change_type == "A":
        package = yaml_data_b_blob.get("package")

        purl = Purl.objects.create(string=package, service=default_service)

        for version in yaml_data_b_blob.get("versions", []):
            create_note(purl, version)

    elif change_type == "M":
        old_package = yaml_data_a_blob.get("package")
        new_package = yaml_data_b_blob.get("package")

        purl = Purl.objects.get(string=old_package, service=default_service)
        purl.string = new_package
        purl.save()

        for version_a, version_b in zip_longest(
            yaml_data_a_blob.get("versions", []), yaml_data_b_blob.get("versions", [])
        ):
            if version_b and not version_a:
                create_note(purl, version_b)

            if version_a and not version_b:
                delete_note(purl, version_b)

            if version_a and version_b:
                try:
                    note = Note.objects.get(acct=purl.acct, content=saneyaml.dump(version_a))
                except Note.DoesNotExist:
                    logger.error("Note Doesn't exist")
                    continue

                if note.content == saneyaml.dump(version_b):
                    continue

                note.content = saneyaml.dump(version_b)
                note.save()

                update_activity = UpdateActivity(actor=purl.to_ap, object=note.to_ap)
                Activity.federated(
                    to=purl.followers_inboxes,
                    body=update_activity.to_ap(),
                    key_id=purl.key_id,
                )

    elif change_type == "D":
        package = yaml_data_a_blob.get("package")
        try:
            purl = Purl.objects.get(string=package, service=default_service)
        except Purl.DoesNotExist:
            logger.error("Invalid Purl")
            return

        for version in yaml_data_a_blob.get("versions", []):
            delete_note(purl, version)

        purl.delete()


def create_note(purl, version):
    """"""
    note = Note.objects.create(acct=purl.acct, content=saneyaml.dump(version))
    purl.notes.add(note)
    create_activity = CreateActivity(actor=purl.to_ap, object=note.to_ap)
    Activity.federated(
        to=purl.followers_inboxes,
        body=create_activity.to_ap(),
        key_id=purl.key_id,
    )


def delete_note(purl, version):
    """"""
    try:
        note = Note.objects.get(acct=purl.acct, content=saneyaml.dump(version))
        note.delete()
        purl.notes.remove(note)

        deleted_activity = DeleteActivity(actor=purl.to_ap, object=note.to_ap)
        Activity.federated(
            to=purl.followers_inboxes,
            body=deleted_activity.to_ap(),
            key_id=purl.key_id,
        )
    except Note.DoesNotExist:
        logger.error("Note Doesn't exist")
