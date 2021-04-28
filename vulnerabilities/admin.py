#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from django.contrib import admin

from vulnerabilities.models import (
    PackageRelatedVulnerability,
    Importer,
    Package,
    Vulnerability,
    VulnerabilityReference,
    VulnerabilitySeverity,
)


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    search_fields = ["vulnerability_id"]


@admin.register(VulnerabilityReference)
class VulnerabilityReferenceAdmin(admin.ModelAdmin):
    search_fields = ["vulnerability__vulnerability_id", "reference_id", "url"]


@admin.register(Package)
class PackageAdmin(admin.ModelAdmin):
    list_filter = ("type", "namespace")
    search_fields = ["name"]


@admin.register(PackageRelatedVulnerability)
class PackageRelatedVulnerabilityAdmin(admin.ModelAdmin):
    list_filter = ("package__type", "package__namespace")
    search_fields = ["vulnerability__vulnerability_id", "package__name"]


@admin.register(Importer)
class ImporterAdmin(admin.ModelAdmin):
    pass


@admin.register(VulnerabilitySeverity)
class VulnerabilitySeverityAdmin(admin.ModelAdmin):
    pass
