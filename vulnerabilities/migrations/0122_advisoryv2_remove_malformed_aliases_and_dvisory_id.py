from django.db import migrations
from django.db.models import Q


class Migration(migrations.Migration):
    dependencies = [
        ("vulnerabilities", "0121_advisoryv2_is_latest_alter_advisoryv2_advisory_id_and_more"),
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
        query = Q()
        for alias_prefix in valid_alias_prefix:
            query |= Q(alias__istartswith=alias_prefix)

        malformed_aliases = AdvisoryAlias.objects.exclude(query)
        AdvisoryV2.objects.filter(aliases__in=malformed_aliases, datasource_id__in=["alpine_linux_importer_v2", "fireeye_importer_v2", "istio_importer_v2", "mattermost_importer_v2"]).delete()
        malformed_aliases.delete()

    operations = [
        migrations.RunPython(drop_malformed_advisory_v2, reverse_code=migrations.RunPython.noop),
    ]
