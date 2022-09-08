#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.contrib import admin

from vulnerabilities.models import Package
from vulnerabilities.models import PackageRelatedVulnerability
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilitySeverity


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    search_fields = ["vulnerability_id"]


@admin.register(VulnerabilityReference)
class VulnerabilityReferenceAdmin(admin.ModelAdmin):
    search_fields = ["vulnerabilityrelatedreference__vulnerability__id", "reference_id", "url"]


@admin.register(Package)
class PackageAdmin(admin.ModelAdmin):
    list_filter = ("type", "namespace")
    search_fields = ["name"]


@admin.register(PackageRelatedVulnerability)
class PackageRelatedVulnerabilityAdmin(admin.ModelAdmin):
    list_filter = ("package__type", "package__namespace")
    search_fields = ["vulnerability__vulnerability_id", "package__name"]


@admin.register(VulnerabilitySeverity)
class VulnerabilitySeverityAdmin(admin.ModelAdmin):
    pass
