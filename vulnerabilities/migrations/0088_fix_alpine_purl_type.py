from datetime import datetime
from datetime import timezone

from aboutcode.pipeline import LoopProgress
from django.db import migrations
from packageurl import PackageURL

CHUNK_SIZE = 50000
BATCH_SIZE = 500


class Migration(migrations.Migration):
    def fix_alpine_purl_type(apps, schema_editor):
        """Use proper apk package type for Alpine"""

        Package = apps.get_model("vulnerabilities", "Package")
        batch = []
        alpine_packages_query = Package.objects.filter(type="alpine")

        log(f"\nFixing PURL for {alpine_packages_query.count():,d} alpine packages")
        progress = LoopProgress(
            total_iterations=alpine_packages_query.count(),
            progress_step=10,
            logger=log,
        )
        for package in progress.iter(alpine_packages_query.iterator(chunk_size=CHUNK_SIZE)):
            package.type = "apk"
            package.namespace = "alpine"

            package.package_url = update_alpine_purl(package.package_url, "apk", "alpine")
            package.plain_package_url = update_alpine_purl(
                package.plain_package_url, "apk", "alpine"
            )

            batch.append(package)
            if len(batch) >= BATCH_SIZE:
                bulk_update_package(Package, batch)
                batch.clear()

        bulk_update_package(Package, batch)

    def reverse_fix_alpine_purl_type(apps, schema_editor):
        Package = apps.get_model("vulnerabilities", "Package")
        batch = []
        alpine_packages_query = Package.objects.filter(type="apk", namespace="alpine")

        log(f"\nREVERSE: Fix for {alpine_packages_query.count():,d} alpine packages")
        progress = LoopProgress(
            total_iterations=alpine_packages_query.count(),
            progress_step=10,
            logger=log,
        )
        for package in progress.iter(alpine_packages_query.iterator(chunk_size=CHUNK_SIZE)):
            package.type = "alpine"
            package.namespace = ""

            package.package_url = update_alpine_purl(package.package_url, "alpine", "")
            package.plain_package_url = update_alpine_purl(package.plain_package_url, "alpine", "")

            batch.append(package)
            if len(batch) >= BATCH_SIZE:
                bulk_update_package(Package, batch)
                batch.clear()

        bulk_update_package(Package, batch)

    dependencies = [
        ("vulnerabilities", "0087_update_alpine_advisory_created_by"),
    ]

    operations = [
        migrations.RunPython(
            code=fix_alpine_purl_type,
            reverse_code=reverse_fix_alpine_purl_type,
        ),
    ]


def bulk_update_package(package, batch):
    if batch:
        package.objects.bulk_update(
            objs=batch,
            fields=[
                "type",
                "namespace",
                "package_url",
                "plain_package_url",
            ],
        )


def update_alpine_purl(purl, purl_type, purl_namespace):
    package_url = PackageURL.from_string(purl).to_dict()
    package_url["type"] = purl_type
    package_url["namespace"] = purl_namespace
    return str(PackageURL(**package_url))


def log(message):
    now_local = datetime.now(timezone.utc).astimezone()
    timestamp = now_local.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    message = f"{timestamp} {message}"
    print(message)
