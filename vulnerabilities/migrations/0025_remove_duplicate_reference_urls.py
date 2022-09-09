from django.db import migrations
from django.db.models import Count
from django.db.models import Max


class Migration(migrations.Migration):

    dependencies = [
        ('vulnerabilities', '0024_alter_all_models_to_add_ordering'),
    ]

    def remove_duplicate_reference_urls(apps, _):
        """
        Find all duplicate references and remove all of them except for one.
        Any duplication will be reprocessed by reimports if needed to correct
        trhe relationships.
        """

        VulnerabilityReference = apps.get_model("vulnerabilities", "VulnerabilityReference")

        duplicates = (
            VulnerabilityReference.objects.values("url")
            .order_by("url")
            .annotate(max_id=Max("id"), count_id=Count("id"))
            .filter(count_id__gt=1)
        )

        for duplicate in duplicates:
            # Get all rows with the same url,
            # exclude the latest one
            # and delete rest of them
            (
                VulnerabilityReference.objects
                .filter(url=duplicate["url"])
                .exclude(id=duplicate["max_id"])
                .delete()
            )

    operations = [
        migrations.RunPython(remove_duplicate_reference_urls, migrations.RunPython.noop),
    ]
