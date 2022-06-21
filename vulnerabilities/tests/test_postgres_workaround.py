#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from datetime import datetime
from datetime import timezone

import pytest
import pytz
from packageurl import PackageURL
from univers.version_constraint import VersionConstraint
from univers.version_range import MavenVersionRange
from univers.versions import MavenVersion

from vulnerabilities import severity_systems
from vulnerabilities.importer import AdvisoryData
from vulnerabilities.importer import AffectedPackage
from vulnerabilities.importer import Reference
from vulnerabilities.importer import VulnerabilitySeverity
from vulnerabilities.models import Advisory

data = AdvisoryData(
    aliases=["CVE-2020-8908", "GHSA-5mg8-w23w-74h3"],
    summary="lore ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore"
    * 1000,
    affected_packages=[
        AffectedPackage(
            package=PackageURL(
                type="maven",
                namespace="com.google.guava",
                name="guava",
                version=None,
                qualifiers={},
                subpath=None,
            ),
            affected_version_range=MavenVersionRange(
                constraints=(
                    VersionConstraint(comparator="<=", version=MavenVersion(string="29.0")),
                )
            ),
            fixed_version=None,
        ),
        AffectedPackage(
            package=PackageURL(
                type="maven",
                namespace="com.google.guava",
                name="guava",
                version=None,
                qualifiers={},
                subpath=None,
            ),
            affected_version_range=MavenVersionRange(
                constraints=(
                    VersionConstraint(comparator="<=", version=MavenVersion(string="29.0")),
                )
            ),
            fixed_version=None,
        ),
        AffectedPackage(
            package=PackageURL(
                type="maven",
                namespace="com.google.guava",
                name="guava",
                version=None,
                qualifiers={},
                subpath=None,
            ),
            affected_version_range=MavenVersionRange(
                constraints=(
                    VersionConstraint(comparator="<=", version=MavenVersion(string="29.0")),
                )
            ),
            fixed_version=None,
        ),
        AffectedPackage(
            package=PackageURL(
                type="maven",
                namespace="com.google.guava",
                name="guava",
                version=None,
                qualifiers={},
                subpath=None,
            ),
            affected_version_range=MavenVersionRange(
                constraints=(
                    VersionConstraint(comparator="<=", version=MavenVersion(string="29.0")),
                )
            ),
            fixed_version=None,
        ),
        AffectedPackage(
            package=PackageURL(
                type="maven",
                namespace="com.google.guava",
                name="guava",
                version=None,
                qualifiers={},
                subpath=None,
            ),
            affected_version_range=MavenVersionRange(
                constraints=(
                    VersionConstraint(comparator="<=", version=MavenVersion(string="29.0")),
                )
            ),
            fixed_version=None,
        ),
        AffectedPackage(
            package=PackageURL(
                type="maven",
                namespace="com.google.guava",
                name="guava",
                version=None,
                qualifiers={},
                subpath=None,
            ),
            affected_version_range=MavenVersionRange(
                constraints=(
                    VersionConstraint(comparator="<=", version=MavenVersion(string="29.0")),
                )
            ),
            fixed_version=None,
        ),
        AffectedPackage(
            package=PackageURL(
                type="maven",
                namespace="com.google.guava",
                name="guava",
                version=None,
                qualifiers={},
                subpath=None,
            ),
            affected_version_range=MavenVersionRange(
                constraints=(
                    VersionConstraint(comparator="<=", version=MavenVersion(string="29.0")),
                )
            ),
            fixed_version=None,
        ),
        AffectedPackage(
            package=PackageURL(
                type="maven",
                namespace="com.google.guava",
                name="guava",
                version=None,
                qualifiers={},
                subpath=None,
            ),
            affected_version_range=MavenVersionRange(
                constraints=(
                    VersionConstraint(comparator="<=", version=MavenVersion(string="29.0")),
                )
            ),
            fixed_version=None,
        ),
        AffectedPackage(
            package=PackageURL(
                type="maven",
                namespace="com.google.guava",
                name="guava",
                version=None,
                qualifiers={},
                subpath=None,
            ),
            affected_version_range=MavenVersionRange(
                constraints=(
                    VersionConstraint(comparator="<=", version=MavenVersion(string="29.0")),
                )
            ),
            fixed_version=None,
        ),
        AffectedPackage(
            package=PackageURL(
                type="maven",
                namespace="com.google.guava",
                name="guava",
                version=None,
                qualifiers={},
                subpath=None,
            ),
            affected_version_range=MavenVersionRange(
                constraints=(
                    VersionConstraint(comparator="<=", version=MavenVersion(string="29.0")),
                )
            ),
            fixed_version=None,
        ),
    ],
    references=[
        Reference(
            reference_id="", url="https://nvd.nist.gov/vuln/detail/CVE-2020-8908", severities=[]
        ),
        Reference(
            reference_id="", url="https://github.com/google/guava/issues/4011", severities=[]
        ),
        Reference(
            reference_id="",
            url="https://github.com/google/guava/commit/fec0dbc4634006a6162cfd4d0d09c962073ddf40",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r215b3d50f56faeb2f9383505f3e62faa9f549bb23e8a9848b78a968e@%3Ccommits.ws.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r4776f62dfae4a0006658542f43034a7fc199350e35a66d4e18164ee6@%3Ccommits.cxf.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r68d86f4b06c808204f62bcb254fcb5b0432528ee8d37a07ef4bc8222@%3Ccommits.ws.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r841c5e14e1b55281523ebcde661ece00b38a0569e00ef5e12bd5f6ba@%3Cissues.maven.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/rb8c0f1b7589864396690fe42a91a71dea9412e86eec66dc85bbacaaf@%3Ccommits.cxf.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/rbc7642b9800249553f13457e46b813bea1aec99d2bc9106510e00ff3@%3Ctorque-dev.db.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/rc2dbc4633a6eea1fcbce6831876cfa17b73759a98c65326d1896cb1a@%3Ctorque-dev.db.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/rd5d58088812cf8e677d99b07f73c654014c524c94e7fedbdee047604@%3Ctorque-dev.db.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://snyk.io/vuln/SNYK-JAVA-COMGOOGLEGUAVA-1015415",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r3c3b33ee5bef0c67391d27a97cbfd89d44f328cf072b601b58d4e748@%3Ccommits.pulsar.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/rfc27e2727a20a574f39273e0432aa97486a332f9b3068f6ac1346594@%3Cdev.myfaces.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/rd01f5ff0164c468ec7abc96ff7646cea3cce6378da2e4aa29c6bcb95@%3Cgithub.arrow.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r037fed1d0ebde50c9caf8d99815db3093c344c3f651c5a49a09824ce@%3Cdev.drill.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r07ed3e4417ad043a27bee7bb33322e9bfc7d7e6d1719b8e3dfd95c14@%3Cdev.drill.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r161b87f8037bbaff400194a63cd2016c9a69f5949f06dcc79beeab54@%3Cdev.drill.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r2fe45d96eea8434b91592ca08109118f6308d60f6d0e21d52438cfb4@%3Cdev.drill.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r6874dfe26eefc41b7c9a5e4a0487846fc4accf8c78ff948b24a1104a@%3Cdev.drill.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://www.oracle.com/security-alerts/cpuApr2021.html",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r007add131977f4f576c232b25e024249a3d16f66aad14a4b52819d21@%3Ccommon-issues.hadoop.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r294be9d31c0312d2c0837087204b5d4bf49d0552890e6eec716fa6a6@%3Cyarn-issues.hadoop.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r3dd8881de891598d622227e9840dd7c2ef1d08abbb49e9690c7ae1bc@%3Cissues.geode.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r49549a8322f62cd3acfa4490d25bfba0be04f3f9ff4d14fe36199d27@%3Cyarn-dev.hadoop.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r58a8775205ab1839dba43054b09a9ab3b25b423a4170b2413c4067ac@%3Ccommon-issues.hadoop.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r5b3d93dfdfb7708e796e8762ab40edbde8ff8add48aba53e5ea26f44@%3Cissues.geode.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r5d61b98ceb7bba939a651de5900dbd67be3817db6bfcc41c6e04e199@%3Cyarn-issues.hadoop.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r79e47ed555bdb1180e528420a7a2bb898541367a29a3bc6bbf0baf2c@%3Cissues.hive.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/r7b0e81d8367264d6cad98766a469d64d11248eb654417809bfdacf09@%3Cyarn-issues.hadoop.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/ra7ab308481ee729f998691e8e3e02e93b1dedfc98f6b1cd3d86923b3@%3Cyarn-issues.hadoop.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/rb2364f4cf4d274eab5a7ecfaf64bf575cedf8b0173551997c749d322@%3Cgitbox.hive.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/rc607bc52f3507b8b9c28c6a747c3122f51ac24afe80af2a670785b97@%3Cissues.geode.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/rcafc3a637d82bdc9a24036b2ddcad1e519dd0e6f848fcc3d606fd78f@%3Cdev.hive.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/rd2704306ec729ccac726e50339b8a8f079515cc29ccb77713b16e7c5@%3Cissues.hive.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/re120f6b3d2f8222121080342c5801fdafca2f5188ceeb3b49c8a1d27@%3Cyarn-issues.hadoop.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/reebbd63c25bc1a946caa419cec2be78079f8449d1af48e52d47c9e85@%3Cissues.geode.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/rf00b688ffa620c990597f829ff85fdbba8bf73ee7bfb34783e1f0d4e@%3Cyarn-dev.hadoop.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/rf9f0fa84b8ae1a285f0210bafec6de2a9eba083007d04640b82aa625@%3Cissues.geode.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://www.oracle.com//security-alerts/cpujul2021.html",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://www.oracle.com/security-alerts/cpuoct2021.html",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://lists.apache.org/thread.html/rd7e12d56d49d73e2b8549694974b07561b79b05455f7f781954231bf@%3Cdev.pig.apache.org%3E",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://www.oracle.com/security-alerts/cpujan2022.html",
            severities=[],
        ),
        Reference(
            reference_id="",
            url="https://security.netapp.com/advisory/ntap-20220210-0003/",
            severities=[],
        ),
        Reference(
            reference_id="GHSA-5mg8-w23w-74h3",
            url="https://github.com/advisories/GHSA-5mg8-w23w-74h3",
            severities=[
                VulnerabilitySeverity(
                    system=severity_systems.CVSS31_QUALITY,
                    value="LOW",
                )
            ],
        ),
    ],
    date_published=datetime(2021, 3, 25, 17, 4, 19, tzinfo=pytz.UTC),
)


@pytest.mark.django_db
def test_postgres_workaround_with_many_references_many_affected_packages_and_long_summary():
    Advisory.objects.get_or_create(
        aliases=data.aliases,
        summary=data.summary,
        affected_packages=[pkg.to_dict() for pkg in data.affected_packages],
        references=[ref.to_dict() for ref in data.references],
        date_published=data.date_published,
        defaults={
            "created_by": "GH-importer",
            "date_collected": datetime.now(tz=timezone.utc),
        },
    )
