from django.db import migrations
from packageurl import PackageURL

class Migration(migrations.Migration):

    def save_purls(apps, schema_editor):
        Package = apps.get_model("vulnerabilities", "Package")
        updatables = []
        for package in Package.objects.all():
            purl = PackageURL(
                type=package.type,
                namespace=package.namespace,
                name=package.name,
                version=package.version,
                qualifiers=package.qualifiers,
                subpath=package.subpath,
            )
            plain_purl = PackageURL(
                type=package.type,
                namespace=package.namespace,
                name=package.name,
                version=package.version,
            ) 
            package.package_url = str(purl)
            package.plain_package_url = str(plain_purl)
            updatables.append(package)
        
        updated = Package.objects.bulk_update(
            objs = updatables,
            fields=["package_url", "plain_package_url"], 
            batch_size=500,
        )
        print(f"Migrated {updated} packages with package_url")            

    dependencies = [
        ("vulnerabilities", "0034_package_package_url_package_plain_package_url"),
    ]

    operations = [
        migrations.RunPython(save_purls, reverse_code=migrations.RunPython.noop),
    ]