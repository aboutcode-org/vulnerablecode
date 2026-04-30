from django.db import migrations
from django.db.models import Q


class Migration(migrations.Migration):
    dependencies = [
        ("vulnerabilities", "0123_alter_packagev2_options_alter_packagev2_package_url_and_more"),
    ]

    def drop_malformed_advisory_v2(apps, _):
        AdvisoryV2 = apps.get_model("vulnerabilities", "AdvisoryV2")
        AdvisoryAlias = apps.get_model("vulnerabilities", "AdvisoryAlias")

        valid_alias_prefix = [
            "cve-", "osv-", "xsa-", "vsv", "zbx-", "zf2", "vu#", "gms-", "usn-",
            "sw-", "ss-", "ts-", "osvdb-", "ysa-", "se-core-", "pysec-", "alpine-",
            "dw2", "go-", "mal-", "zdi-can", "asa-", "ezsa-", "ghsl-", "ghsa-",
            "talos-", "srcclr-sid-", "bit-", "gnutls-", "rustsec-", "snyk-",
            "temp-", "TYPO3-", "wnpa-sec-", "sa-core-", "skcsirt-", "flow-", "gsd-"
        ]

        target_importers = ["alpine_linux_importer_v2",
                            "fireeye_importer_v2",
                            "istio_importer_v2",
                            "mattermost_importer_v2"]
        query = Q()
        for alias_prefix in valid_alias_prefix:
            query |= Q(alias__istartswith=alias_prefix)

        malformed_alias_ids = list(
            AdvisoryAlias.objects.filter(
                advisories__datasource_id__in=target_importers
            ).exclude(query).values_list('id', flat=True).distinct()
        )

        AdvisoryV2.objects.filter(
            datasource_id__in=target_importers,
            aliases__id__in=malformed_alias_ids
        ).delete()

        AdvisoryAlias.objects.filter(
            id__in=malformed_alias_ids,
            advisories__isnull=True
        ).delete()

    operations = [
        migrations.RunPython(drop_malformed_advisory_v2, reverse_code=migrations.RunPython.noop),
    ]
