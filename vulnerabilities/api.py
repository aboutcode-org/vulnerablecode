#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from urllib.parse import unquote

from django_filters import rest_framework as filters
from packageurl import PackageURL
from rest_framework import serializers
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from vulnerabilities.models import Alias
from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilitySeverity


class VulnerabilitySeveritySerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilitySeverity
        fields = ["value", "scoring_system"]


class VulnerabilityReferenceSerializer(serializers.ModelSerializer):
    scores = VulnerabilitySeveritySerializer(many=True, source="vulnerabilityseverity_set")
    reference_url = serializers.CharField(source="url")

    class Meta:
        model = VulnerabilityReference
        fields = ["reference_url", "reference_id", "scores", "url"]


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
        fields = ["url", "vulnerability_id", "summary", "references"]


class AliasSerializer(serializers.HyperlinkedModelSerializer):
    """
    Used for nesting inside package focused APIs.
    """

    class Meta:
        model = Alias
        fields = ["alias"]


class VulnerabilitySerializer(serializers.HyperlinkedModelSerializer):

    fixed_packages = MinimalPackageSerializer(many=True, source="resolved_to", read_only=True)
    affected_packages = MinimalPackageSerializer(many=True, source="vulnerable_to", read_only=True)

    references = VulnerabilityReferenceSerializer(many=True, source="vulnerabilityreference_set")
    aliases = AliasSerializer(many=True, source="alias")

    class Meta:
        model = Vulnerability
        fields = [
            "url",
            "vulnerability_id",
            "summary",
            "aliases",
            "fixed_packages",
            "affected_packages",
            "references",
        ]


class PackageSerializer(serializers.HyperlinkedModelSerializer):
    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["unresolved_vulnerabilities"] = data["affected_by_vulnerabilities"]
        return data

    purl = serializers.CharField(source="package_url")
    affected_by_vulnerabilities = MinimalVulnerabilitySerializer(
        many=True, source="vulnerable_to", read_only=True
    )
    fixing_vulnerabilities = MinimalVulnerabilitySerializer(
        many=True, source="resolved_to", read_only=True
    )
    fixed_packages = MinimalPackageSerializer(many=True, read_only=True)

    class Meta:
        model = Package
        fields = [
            "url",
            "purl",
            "type",
            "namespace",
            "name",
            "version",
            "qualifiers",
            "subpath",
            "affected_by_vulnerabilities",
            "fixed_packages",
            "fixing_vulnerabilities",
        ]


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
    paginate_by = 50
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = PackageFilterSet

    # TODO: Fix the swagger documentation for this endpoint
    @action(detail=False, methods=["post"])
    def bulk_search(self, request):
        """
        See https://github.com/nexB/vulnerablecode/pull/369#issuecomment-796877606 for docs
        """
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
            except ValueError:
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


class CPEFilterSet(filters.FilterSet):
    cpe = filters.CharFilter(method="filter_cpe")

    def filter_cpe(self, queryset, name, value):
        cpe = unquote(value)
        return self.queryset.filter(vulnerabilityreference__reference_id__startswith=cpe).distinct()


class CPEViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Vulnerability.objects.filter(
        vulnerabilityreference__reference_id__startswith="cpe"
    ).distinct()
    serializer_class = VulnerabilitySerializer
    paginate_by = 50
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = CPEFilterSet


class AliasFilterSet(filters.FilterSet):
    alias = filters.CharFilter(method="filter_alias")

    def filter_alias(self, queryset, name, value):
        alias = unquote(value)
        return self.queryset.filter(aliases__alias__icontains=alias)


class AliasViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    paginate_by = 50
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = AliasFilterSet
