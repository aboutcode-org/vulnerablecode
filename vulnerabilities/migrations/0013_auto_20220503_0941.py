from django.db import migrations

from django.utils.http import int_to_base36

class Migration(migrations.Migration):

    dependencies = [
        ('vulnerabilities', '0012_alter_vulnerability_vulnerability_id'),
    ]

    def save_vulnerability_id(apps, schema_editor):
        Vulnerabilities = apps.get_model("vulnerabilities", "Vulnerability")
        for vulnerability in Vulnerabilities.objects.all():
            if not vulnerability.vulnerability_id:
                vulnerability.vulnerability_id = f"VULCOID-{int_to_base36(vulnerability.id).upper()}"
                vulnerability.save()

    operations = [
        migrations.RunPython(save_vulnerability_id)
    ]
