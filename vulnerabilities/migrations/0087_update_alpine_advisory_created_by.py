
from django.db import migrations

"""
Update the created_by field on Advisory from the old qualified_name
to the new pipeline_id.
"""


def update_created_by(apps, schema_editor):
    from vulnerabilities.pipelines.alpine_linux_importer import AlpineLinuxImporterPipeline

    Advisory = apps.get_model("vulnerabilities", "Advisory")
    Advisory.objects.filter(created_by="vulnerabilities.importers.alpine_linux.AlpineImporter").update(
        created_by=AlpineLinuxImporterPipeline.pipeline_id
    )


def reverse_update_created_by(apps, schema_editor):
    from vulnerabilities.pipelines.alpine_linux_importer import AlpineLinuxImporterPipeline

    Advisory = apps.get_model("vulnerabilities", "Advisory")
    Advisory.objects.filter(created_by=AlpineLinuxImporterPipeline.pipeline_id).update(
        created_by="vulnerabilities.importers.alpine_linux.AlpineImporter"
    )


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0086_codefix"),
    ]

    operations = [
        migrations.RunPython(update_created_by, reverse_code=reverse_update_created_by),
    ]