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
from typing import List

from django.db.models import Q
from django.urls import reverse
from django_filters import rest_framework as filters
from packageurl import PackageURL
from rest_framework import serializers
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, inline_serializer
from drf_spectacular.types import OpenApiTypes

from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference

# This serializer is used for the bulk apis, to prevent wrong auto documentation
# TODO: Fix the swagger documentation for bulk apis
placeholder_serializer = inline_serializer(name="Placeholder", fields={})


class VulnerabilityReferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilityReference
        fields = [
            "source",
            "reference_id",
            "url",
        ]


class HyperLinkedPackageSerializer(serializers.HyperlinkedModelSerializer):
    purl = serializers.CharField(source="package_url")

    class Meta:
        model = Package
        fields = ["url", "purl"]


class HyperLinkedVulnerabilitySerializer(serializers.HyperlinkedModelSerializer):

    class Meta:
        model = Vulnerability
        fields = ["url", "vulnerability_id"]


class MinimalVulnerabilitySerializer(serializers.HyperlinkedModelSerializer):

    resolved_packages = HyperLinkedPackageSerializer(
        many=True, source="resolved_to", read_only=True
    )
    unresolved_packages = HyperLinkedPackageSerializer(
        many=True, source="vulnerable_to", read_only=True
    )

    class Meta:
        model = Vulnerability
        fields = ["url", "unresolved_packages", "resolved_packages"]


class VulnerabilitySerializer(MinimalVulnerabilitySerializer):
    references = VulnerabilityReferenceSerializer(many=True, source="vulnerabilityreference_set")

    class Meta:
        model = Vulnerability
        fields = "__all__"


class MinimalPackageSerializer(serializers.HyperlinkedModelSerializer):
    unresolved_vulnerabilities = HyperLinkedVulnerabilitySerializer(
        many=True, source="vulnerable_to", read_only=True
    )
    resolved_vulnerabilities = HyperLinkedVulnerabilitySerializer(
        many=True, source="resolved_to", read_only=True
    )

    class Meta:
        model = Package
        fields = [
            "resolved_vulnerabilities",
            "unresolved_vulnerabilities",
        ]


class PackageSerializer(MinimalPackageSerializer):
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

    # TODO: Fix the swagger documentation for this endpoint
    @extend_schema(request=placeholder_serializer, responses=placeholder_serializer)
    @action(detail=False, methods=["post"])
    def bulk_search(self, request):
        """
        See https://github.com/nexB/vulnerablecode/pull/303#issuecomment-761801639 for docs
        """
        filter_list = Q()
        response = {}
        if not isinstance(request.data.get("packages"), list):
            return Response(
                status=400,
                data={
                    "Error": "Request needs to contain a key 'packages' which has the value of a list of package urls"  # nopep8
                },
            )
        for purl in request.data["packages"]:
            try:
                filter_list |= Q(
                    **{k: v for k, v in PackageURL.from_string(purl).to_dict().items() if v}
                )
            except ValueError as ve:
                return Response(status=400, data={"Error": str(ve)})

            # This handles the case when the said purl doesnt exist in db
            response[purl] = {}
        res = Package.objects.filter(filter_list)
        for p in res:
            response[p.package_url] = MinimalPackageSerializer(p, context={"request": request}).data

        return Response(response)


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

    # TODO: Fix the swagger documentation for this endpoint
    @extend_schema(request=placeholder_serializer, responses=placeholder_serializer)
    @action(detail=False, methods=["post"])
    def bulk_search(self, request):
        """
        See https://github.com/nexB/vulnerablecode/pull/303#issuecomment-761801619 for docs
        """
        filter_list = []
        response = {}
        if not isinstance(request.data.get("vulnerabilities"), list):
            return Response(
                status=400,
                data={
                    "Error": "Request needs to contain a key 'vulnerabilities' which has the value of a list of vulnerability ids"  # nopep8
                },
            )

        for vulnerability_id in request.data["vulnerabilities"]:
            filter_list.append(vulnerability_id)
            # This handles the case when the said cve doesnt exist in db
            response[vulnerability_id] = {}
        res = Vulnerability.objects.filter(vulnerability_id__in=filter_list)
        for vuln in res:
            response[vuln.vulnerability_id] = MinimalVulnerabilitySerializer(
                vuln, context={"request": request}
            ).data
        return Response(response)
