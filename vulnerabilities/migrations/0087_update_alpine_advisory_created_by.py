
from django.db import migrations

"""
Update the created_by field on Advisory from the old qualified_name
to the new pipeline_id.
"""


def update_created_by(apps, schema_editor):
    # Remove pipeline import path, since we are removing V1/V2 code
    Advisory = apps.get_model("vulnerabilities", "Advisory")
    Advisory.objects.filter(created_by="vulnerabilities.importers.alpine_linux.AlpineImporter").update(
        created_by="alpine_importer"
    )


def reverse_update_created_by(apps, schema_editor):
    # Remove pipeline import path, since we are removing V1/V2 code
    Advisory = apps.get_model("vulnerabilities", "Advisory")
    Advisory.objects.filter(created_by="alpine_importer").update(
        created_by="vulnerabilities.importers.alpine_linux.AlpineImporter"
    )


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0086_codefix"),
    ]

    operations = [
        migrations.RunPython(update_created_by, reverse_code=reverse_update_created_by),
    ]