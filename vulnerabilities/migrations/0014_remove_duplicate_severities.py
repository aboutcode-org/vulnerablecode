from django.db import migrations
from django.db.models import Count
from django.db.models import Max


class Migration(migrations.Migration):

    dependencies = [
        ("vulnerabilities", "0013_auto_20220503_0941"),
    ]

    def remove_duplicate_rows(apps, schema_editor):
        """
        Find all duplicate rows and remove all of them except the latest one.
        """
        unique_fields = [
            "reference",
            "scoring_system",
            "value",
        ]
        Severities = apps.get_model("vulnerabilities", "VulnerabilitySeverity")
        # Get all duplicates according to the unique_fields
        duplicates = (
            Severities.objects.values(*unique_fields)
            .order_by()
            .annotate(max_id=Max("id"), count_id=Count("id"))
            .filter(count_id__gt=1)
        )
        for duplicate in duplicates:
            unique_fields_data = {
                uniqe_field: duplicate[uniqe_field] for uniqe_field in unique_fields
            }
            # Get all rows with the same unique_fields_data
            # exclude the latest one
            # and delete rest of them
            (
                Severities.objects.filter(**unique_fields_data)
                .exclude(id=duplicate["max_id"])
                .delete()
            )

    # sepecifying migrations.RunPython.noop as reverse_code
    operations = [migrations.RunPython(remove_duplicate_rows, migrations.RunPython.noop)]
