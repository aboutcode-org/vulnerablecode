#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
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
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from django.urls import reverse
from rest_framework import serializers
from rest_framework import viewsets

from packageurl import PackageURL

from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference


class VulnerabilityReferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilityReference
        fields = [
            "source",
            "reference_id",
            "url",
        ]


class VulnerabilitySerializer(serializers.ModelSerializer):
    references = VulnerabilityReferenceSerializer(many=True, source="vulnerabilityreference_set")
    resolved_packages = serializers.SerializerMethodField()
    unresolved_packages = serializers.SerializerMethodField()

    class Meta:
        model = Vulnerability
        fields = "__all__"

    def get_resolved_packages(self, vulnerability):
        request = self.context.get("request")

        # Instead of iterating and querying the db for eve id FOR EACH  item
        # in `resolved_to`, consider prefetching all cve_id of `resolved_to` in one query.
        return [
            {
                "purl": Package.objects.get(id=rel.package_id).package_url,
                "url": request.build_absolute_uri(
                    reverse("package-detail", kwargs={"pk": rel.package_id})
                ),
            }
            for rel in vulnerability.resolved_to
        ]

    def get_unresolved_packages(self, vulnerability):
        request = self.context.get("request")

        # Instead of iterating and querying the db for eve id FOR EACH  item
        # in `vulnerable_to`, consider prefetching all cve_id of vulnerable_to` in one query.
        return [
            {
                "purl": Package.objects.get(id=rel.package_id).package_url,
                "url": request.build_absolute_uri(
                    reverse("package-detail", kwargs={"pk": rel.package_id})
                ),
            }
            for rel in vulnerability.vulnerable_to
        ]


class PackageSerializer(serializers.ModelSerializer):
    unresolved_vulnerabilities = serializers.SerializerMethodField()
    resolved_vulnerabilities = serializers.SerializerMethodField()
    purl = serializers.CharField(source="package_url")

    class Meta:
        model = Package
        fields = [
            "type",
            "namespace",
            "name",
            "version",
            "qualifiers",
            "subpath",
            "purl",
            "resolved_vulnerabilities",
            "unresolved_vulnerabilities",
        ]

    def get_unresolved_vulnerabilities(self, package):
        request = self.context["request"]

        # Instead of iterating and querying the db for eve id FOR EACH  item
        # in `vulnerable_to`, consider prefetching all cve_id of vulnerable_to` in one query.
        return [
            {
                "vulnerability_id": Vulnerability.objects.get(id=i.vulnerability_id).cve_id,
                "url": request.build_absolute_uri(
                    reverse("vulnerability-detail", kwargs={"pk": i.vulnerability_id})
                ),
            }
            for i in package.vulnerable_to
        ]

    def get_resolved_vulnerabilities(self, package):
        request = self.context["request"]

        # Instead of iterating and querying the db for eve id FOR EACH  item
        # in `resolved_to`, consider prefetching all cve_id of `resolved_to` in one query.
        return [
            {
                "vulnerability_id": Vulnerability.objects.get(id=i.vulnerability_id).cve_id,
                "url": request.build_absolute_uri(
                    reverse("vulnerability-detail", kwargs={"pk": i.vulnerability_id})
                ),
            }
            for i in package.resolved_to
        ]


class PackageViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Package.objects.all()
    serializer_class = PackageSerializer
    filterset_fields = ("name", "version", "namespace", "type", "subpath")

    def filter_queryset(self, qs):
        purl = self.request.query_params.get("purl")
        if not purl:
            return super().filter_queryset(qs)

        try:
            purl = PackageURL.from_string(purl)
        except ValueError as ve:
            raise serializers.ValidationError(
                detail={"error": f'"{purl}" is not a valid Package URL: {ve}'},
            )

        attrs = {k: v for k, v in purl.to_dict().items() if v}
        return self.queryset.filter(**attrs)


class VulnerabilityView(viewsets.ReadOnlyModelViewSet):
    serializer_class = VulnerabilitySerializer
    paginate_by = 50

    def get_queryset(self):
        if "vulnerability_id" in self.request.query_params:
            return Vulnerability.objects.filter(
                cve_id__contains=self.request.query_params["vulnerability_id"]
            )

        return Vulnerability.objects.all()

    def get_serializer_context(self):
        context = super(VulnerabilityView, self).get_serializer_context()
        # Passing this context allows construction of absolute urls.
        context.update({"request": self.request})
        return context
