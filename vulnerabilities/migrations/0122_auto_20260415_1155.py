from django.db import migrations
from django.db.models import F, Window
from django.db.models.functions import RowNumber


def remove_duplicate_package_urls(apps, schema_editor):
    PackageV2 = apps.get_model("vulnerabilities", "PackageV2")

    duplicates = (
        PackageV2.objects
        .annotate(
            rn=Window(
                expression=RowNumber(),
                partition_by=[F("package_url")],
                order_by=F("id").desc(),
            )
        )
        .filter(rn__gt=1)
    )

    BATCH_SIZE = 1000
    ids = list(duplicates.values_list("id", flat=True))

    for i in range(0, len(ids), BATCH_SIZE):
        PackageV2.objects.filter(id__in=ids[i:i+BATCH_SIZE]).delete()


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0121_advisoryv2_is_latest_alter_advisoryv2_advisory_id_and_more"),
    ]

    operations = [
        migrations.RunPython(remove_duplicate_package_urls, migrations.RunPython.noop),
    ]