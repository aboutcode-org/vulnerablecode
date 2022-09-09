from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('vulnerabilities', '0019_alter_vulnerabilityreference_options'),
    ]

    def delete_reference_with_empty_urls(apps, _):
        """
        Delete all references with empty URLs.
        """
        Reference = apps.get_model("vulnerabilities", "VulnerabilityReference")
        Reference.objects.filter(url="").delete()

    operations = [
        migrations.RunPython(delete_reference_with_empty_urls, migrations.RunPython.noop),
    ]
