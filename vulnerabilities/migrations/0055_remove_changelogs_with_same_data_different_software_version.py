from django.db import migrations
from django.db import models


class Migration(migrations.Migration):

    def remove_duped_changelogs(apps, schema_editor):
        ChangeLog = apps.get_model("vulnerabilities", "ChangeLog")
        # Identify duplicate records based on actor_name, action_type, and source_url
        duplicate_records = ChangeLog.objects.values('actor_name', 'action_type', 'source_url').annotate(count=models.Count('id')).filter(count__gt=1)

        to_be_deleted = list()

        for duplicate_set in duplicate_records:
            # Get the records for the current duplicate set
            records_to_delete = ChangeLog.objects.filter(
                actor_name=duplicate_set['actor_name'],
                action_type=duplicate_set['action_type'],
                source_url=duplicate_set['source_url']
            ).order_by('-software_version')

            # Keep the record with the older software version
            record_to_keep = records_to_delete.last()

            # Delete the records with the newer software version
            to_be_deleted.extend(records_to_delete.exclude(id=record_to_keep.id))

        to_be_deleted = set(to_be_deleted)
        ChangeLog.objects.filter(id__in = to_be_deleted).delete()

    dependencies = [
        ("vulnerabilities", "0054_alter_packagechangelog_software_version_and_more"),
    ]

    operations = [
        migrations.RunPython(remove_duped_changelogs, reverse_code=migrations.RunPython.noop),
    ]