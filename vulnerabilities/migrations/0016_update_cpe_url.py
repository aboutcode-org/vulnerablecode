from django.db import migrations

class Migration(migrations.Migration):

    def update_cpe_url(apps, schema_editor):
        Reference = apps.get_model("vulnerabilities", "VulnerabilityReference")
        for reference in Reference.objects.filter(reference_id__startswith="cpe"):
            cpe = reference.reference_id
            base_url = 'https://nvd.nist.gov/vuln/search/results'
            params = '?adv_search=true&isCpeNameSearch=true'
            vuln_url = f'{base_url}{params}&query={cpe}'
            reference.url = vuln_url
            reference.save()

    dependencies = [
        ('vulnerabilities', '0015_alter_vulnerabilityseverity_unique_together_and_more'),
    ]

    operations = [
        migrations.RunPython(update_cpe_url, migrations.RunPython.noop),
    ]
