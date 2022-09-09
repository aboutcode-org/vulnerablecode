from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('vulnerabilities', '0016_update_cpe_url'),
    ]

    def delete_reference_to_cpes_with_empty_urls(apps, _):
        """
        Delete references to CPEs with empty URLs.
        https://github.com/nexB/vulnerablecode/issues/818#issuecomment-1206437637
        """
        Reference = apps.get_model("vulnerabilities", "VulnerabilityReference")
        Reference.objects.filter(reference_id__startswith="cpe", url="").delete()

    operations = [
        migrations.RunPython(delete_reference_to_cpes_with_empty_urls, migrations.RunPython.noop),
    ]
