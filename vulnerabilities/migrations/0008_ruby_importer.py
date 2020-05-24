from django.db import migrations


def add_ruby_importer(apps, _):
    Importer = apps.get_model('vulnerabilities', 'Importer')

    Importer.objects.create(
        name='ruby',
        license='',
        last_run=None,
        data_source='rubyDataSource',
        data_source_cfg={
            'repository_url': 'https://github.com/rubysec/ruby-advisory-db.git',
        },
    )


def remove_ruby_importer(apps, _):
    Importer = apps.get_model('vulnerabilities', 'Importer')
    qs = Importer.objects.filter(name='rubyy')
    if qs:
        qs[0].delete()


class Migration(migrations.Migration):

    dependencies = [
        ('vulnerabilities', '0007_npm_importer'),
    ]

    operations = [
        migrations.RunPython(add_ruby_importer, remove_ruby_importer),
    ]
