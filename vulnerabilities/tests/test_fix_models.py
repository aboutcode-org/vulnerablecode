#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.contrib.auth import get_user_model
from django.test import TestCase
from packageurl import PackageURL

from vulnerabilities.models import Package
from vulnerabilities.models import PackageRelatedVulnerability
from vulnerabilities.models import Vulnerability

User = get_user_model()


class TestPackageModel(TestCase):
    def setUp(self):
        vuln1 = Vulnerability.objects.create(
            summary="test-vuln",
        )
        vuln2 = Vulnerability.objects.create(
            summary="test-vuln1",
        )
        for i in range(0, 10):
            query_kwargs = dict(
                type="generic",
                namespace="nginx",
                name="test",
                version=str(i),
                qualifiers={},
                subpath="",
            )
            vuln_package = Package.objects.create(**query_kwargs)
            # Attaching same package to 2 vulnerabilities
            PackageRelatedVulnerability.objects.create(
                package=vuln_package,
                vulnerability=vuln1,
                fix=False,
            )
            PackageRelatedVulnerability.objects.create(
                package=vuln_package,
                vulnerability=vuln2,
                fix=False,
            )

    def test_get_vulnerable_packages(self):
        vuln_packages = Package.objects.vulnerable()
        assert vuln_packages.count() == 10
        vuln_purls = [pkg.purl for pkg in vuln_packages.only(*PackageURL._fields)]
        assert vuln_purls == [
            "pkg:generic/nginx/test@0",
            "pkg:generic/nginx/test@1",
            "pkg:generic/nginx/test@2",
            "pkg:generic/nginx/test@3",
            "pkg:generic/nginx/test@4",
            "pkg:generic/nginx/test@5",
            "pkg:generic/nginx/test@6",
            "pkg:generic/nginx/test@7",
            "pkg:generic/nginx/test@8",
            "pkg:generic/nginx/test@9",
        ]
