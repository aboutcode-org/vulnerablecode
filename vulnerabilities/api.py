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

from urllib.parse import unquote

from django.db.models import Q
from django.urls import reverse
from django_filters import rest_framework as filters
from drf_spectacular.utils import extend_schema, inline_serializer
from packageurl import PackageURL

from rest_framework import serializers, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilitySeverity

# This serializer is used for the bulk apis, to prevent wrong auto documentation
# TODO: Fix the swagger documentation for bulk apis
placeholder_serializer = inline_serializer(name="Placeholder", fields={})


class VulnerabilitySeveritySerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilitySeverity
        fields = ["value", "scoring_system"]


class VulnerabilityReferenceSerializer(serializers.ModelSerializer):
    scores = VulnerabilitySeveritySerializer(many=True)

    class Meta:
        model = VulnerabilityReference
        fields = ["source", "reference_id", "url", "scores"]


class MinimalPackageSerializer(serializers.HyperlinkedModelSerializer):
    """
    Used for nesting inside vulnerability focused APIs.
    """

    purl = serializers.CharField(source="package_url")

    class Meta:
        model = Package
        fields = ["url", "purl"]


class MinimalVulnerabilitySerializer(serializers.HyperlinkedModelSerializer):
    """
    Used for nesting inside package focused APIs.
    """

    references = VulnerabilityReferenceSerializer(many=True, source="vulnerabilityreference_set")

    class Meta:
        model = Vulnerability
        fields = ["url", "vulnerability_id", "references"]


class VulnerabilitySerializer(serializers.HyperlinkedModelSerializer):

    resolved_packages = MinimalPackageSerializer(many=True, source="resolved_to", read_only=True)
    unresolved_packages = MinimalPackageSerializer(
        many=True, source="vulnerable_to", read_only=True
    )

    references = VulnerabilityReferenceSerializer(many=True, source="vulnerabilityreference_set")

    class Meta:
        model = Vulnerability
        fields = "__all__"


class PackageSerializer(serializers.HyperlinkedModelSerializer):

    unresolved_vulnerabilities = MinimalVulnerabilitySerializer(
        many=True, source="vulnerable_to", read_only=True
    )
    resolved_vulnerabilities = MinimalVulnerabilitySerializer(
        many=True, source="resolved_to", read_only=True
    )
    purl = serializers.CharField(source="package_url")

    class Meta:
        model = Package
        exclude = ["vulnerabilities"]


class PackageFilterSet(filters.FilterSet):
    purl = filters.CharFilter(method="filter_purl")

    class Meta:
        model = Package
        fields = ["name", "type", "version", "subpath", "purl"]

    def filter_purl(self, queryset, name, value):
        purl = unquote(value)
        try:
            purl = PackageURL.from_string(purl)

        except ValueError as ve:
            raise serializers.ValidationError(
                detail={"error": f'"{purl}" is not a valid Package URL: {ve}'},
            )

        attrs = {k: v for k, v in purl.to_dict().items() if v}
        return self.queryset.filter(**attrs)


class PackageViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Package.objects.all()
    serializer_class = PackageSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = PackageFilterSet

    class PackageBulkRequestSerializer(serializers.Serializer):
        purls = serializers.ListField(child=serializers.CharField(max_length=100))

    class PackageBulkResponseSerializer(serializers.Serializer):
        result = serializers.ListField(child=PackageSerializer())

    @extend_schema(request=PackageBulkRequestSerializer, responses=PackageBulkResponseSerializer)
    @action(detail=False, methods=["post"])
    def bulk_search(self, request):
        response = []
        purls = request.data.get("purls", []) or []
        if not purls or not isinstance(purls, list):
            return Response(
                status=400,
                data={"Error": "A non-empty 'purls' list of package URLs is required."},
            )
        for purl in request.data["purls"]:
            try:
                purl_string = purl
                purl = PackageURL.from_string(purl).to_dict()
            except ValueError as ve:
                return Response(status=400, data={"Error": f"Invalid Package URL: {purl}"})
            purl_data = Package.objects.filter(
                **{key: value for key, value in purl.items() if value}
            )
            purl_response = {}
            if purl_data:
                purl_response = PackageSerializer(purl_data[0], context={"request": request}).data
            else:
                purl_response = purl
                purl_response["unresolved_vulnerabilities"] = []
                purl_response["resolved_vulnerabilities"] = []
                purl_response["purl"] = purl_string
            response.append(purl_response)
        res = {"result": response}
        return Response(res)


class VulnerabilityFilterSet(filters.FilterSet):
    class Meta:
        model = Vulnerability
        fields = ["vulnerability_id"]


class VulnerabilityViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    paginate_by = 50
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = VulnerabilityFilterSet
