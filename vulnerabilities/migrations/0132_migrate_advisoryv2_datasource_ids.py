from django.db import migrations
from django.db.models import F
from django.db.models import Value
from django.db.models.functions import Concat


def migrate_advisoryv2_datasource_ids(apps, schema_editor):
    """
    v2 importers previously stored pipeline_id as datasource_id on AdvisoryV2.
    Migration 0131 copied that value into pipeline_id; update datasource_id (and avid)
    to each pipeline's datasource_id, matching rows by pipeline_id.
    """
    from vulnerabilities.importers import IMPORTERS_REGISTRY
    from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2

    Advisory = apps.get_model("vulnerabilities", "AdvisoryV2")

    for pipeline_class in IMPORTERS_REGISTRY.values():
        if not issubclass(pipeline_class, VulnerableCodeBaseImporterPipelineV2):
            continue

        pipeline_id = pipeline_class.pipeline_id
        datasource_id = pipeline_class.datasource_id
        if not pipeline_id or not datasource_id:
            continue
        if pipeline_id == datasource_id:
            continue

        Advisory.objects.filter(
            pipeline_id=pipeline_id,
            datasource_id=pipeline_id,
        ).update(
            datasource_id=datasource_id,
            avid=Concat(Value(f"{datasource_id}/"), F("advisory_id")),
        )


def reverse_migrate_advisoryv2_datasource_ids(apps, schema_editor):
    from vulnerabilities.importers import IMPORTERS_REGISTRY
    from vulnerabilities.pipelines import VulnerableCodeBaseImporterPipelineV2

    Advisory = apps.get_model("vulnerabilities", "AdvisoryV2")

    for pipeline_class in IMPORTERS_REGISTRY.values():
        if not issubclass(pipeline_class, VulnerableCodeBaseImporterPipelineV2):
            continue
        if "v2_importers" not in pipeline_class.__module__:
            continue

        pipeline_id = pipeline_class.pipeline_id
        datasource_id = pipeline_class.datasource_id
        if not pipeline_id or not datasource_id:
            continue
        if pipeline_id == datasource_id:
            continue

        Advisory.objects.filter(
            pipeline_id=pipeline_id,
            datasource_id=datasource_id,
        ).update(
            datasource_id=pipeline_id,
            avid=Concat(Value(f"{pipeline_id}/"), F("advisory_id")),
        )


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0131_auto_20260518_0854"),
    ]

    operations = [
        migrations.RunPython(
            migrate_advisoryv2_datasource_ids,
            reverse_code=reverse_migrate_advisoryv2_datasource_ids,
        ),
    ]
