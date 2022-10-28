#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from urllib.parse import unquote

from django.db.models import Prefetch
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
from vulnerabilities.models import get_purl_query_lookups
from vulnerabilities.throttling import StaffUserRateThrottle


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
        fields = ["url", "purl", "is_vulnerable"]


class VulnSerializerRefsAndSummary(serializers.HyperlinkedModelSerializer):
    """
    Used for nesting inside package focused APIs.
    """

    fixed_packages = MinimalPackageSerializer(
        many=True, source="filtered_fixed_packages", read_only=True
    )

    references = VulnerabilityReferenceSerializer(many=True, source="vulnerabilityreference_set")

    class Meta:
        model = Vulnerability
        fields = ["url", "vulnerability_id", "summary", "references", "fixed_packages"]


class MinimalVulnerabilitySerializer(serializers.HyperlinkedModelSerializer):
    """
    Used for nesting inside package focused APIs.
    """

    class Meta:
        model = Vulnerability
        fields = ["url", "vulnerability_id"]


class AliasSerializer(serializers.HyperlinkedModelSerializer):
    """
    Used for nesting inside package focused APIs.
    """

    class Meta:
        model = Alias
        fields = ["alias"]


class VulnerabilitySerializer(serializers.HyperlinkedModelSerializer):

    fixed_packages = MinimalPackageSerializer(
        many=True, source="filtered_fixed_packages", read_only=True
    )
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

    affected_by_vulnerabilities = serializers.SerializerMethodField("get_affected_vulnerabilities")

    fixing_vulnerabilities = serializers.SerializerMethodField("get_fixed_vulnerabilities")

    def get_fixed_packages(self, package):
        """
        Return a queryset of all packages that fixes a vulnerability with
        same type, namespace, name, subpath and qualifiers of the `package`
        """
        return Package.objects.filter(
            name=package.name,
            namespace=package.namespace,
            type=package.type,
            qualifiers=package.qualifiers,
            subpath=package.subpath,
            packagerelatedvulnerability__fix=True,
        ).distinct()

    def get_vulnerabilities_for_a_package(self, package, fix) -> dict:
        """
        Return a mapping of vulnerabilities data related to the given `package`.
        Return vulnerabilities that affects the `package` if given `fix` flag is False,
        otherwise return vulnerabilities fixed by the `package`.
        """
        fixed_packages = self.get_fixed_packages(package=package)
        qs = package.vulnerabilities.filter(packagerelatedvulnerability__fix=fix)
        qs = qs.prefetch_related(
            Prefetch(
                "packages",
                queryset=fixed_packages,
                to_attr="filtered_fixed_packages",
            )
        )
        return VulnSerializerRefsAndSummary(
            instance=qs,
            many=True,
            context={"request": self.context["request"]},
        ).data

    def get_fixed_vulnerabilities(self, package) -> dict:
        """
        Return a mapping of vulnerabilities fixed in the given `package`.
        """
        return self.get_vulnerabilities_for_a_package(package=package, fix=True)

    def get_affected_vulnerabilities(self, package) -> dict:
        """
        Return a mapping of vulnerabilities that affects the given `package`.
        """
        return self.get_vulnerabilities_for_a_package(package=package, fix=False)

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
            "fixing_vulnerabilities",
        ]


class PackageFilterSet(filters.FilterSet):
    purl = filters.CharFilter(method="filter_purl")

    class Meta:
        model = Package
        fields = [
            "name",
            "type",
            "version",
            "subpath",
            "purl",
            "namespace",
            "packagerelatedvulnerability__fix",
        ]

    def filter_purl(self, queryset, name, value):
        purl = unquote(value)
        try:
            purl = PackageURL.from_string(purl)

        except ValueError as ve:
            raise serializers.ValidationError(
                detail={"error": f'"{purl}" is not a valid Package URL: {ve}'},
            )

        lookups = get_purl_query_lookups(purl)
        return self.queryset.filter(**lookups)


class PackageViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Lookup for vulnerable packages by Package URL.
    """

    queryset = Package.objects.all()
    serializer_class = PackageSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = PackageFilterSet
    throttle_classes = [StaffUserRateThrottle]
    throttle_scope = "packages"

    # TODO: Fix the swagger documentation for this endpoint
    @action(detail=False, methods=["post"], throttle_scope="bulk_search_packages")
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
                purl = PackageURL.from_string(purl)
            except ValueError:
                return Response(status=400, data={"Error": f"Invalid Package URL: {purl}"})
            lookups = get_purl_query_lookups(purl)
            purl_data = Package.objects.filter(**lookups)
            purl_response = {}
            if purl_data:
                purl_response = PackageSerializer(purl_data[0], context={"request": request}).data
            else:
                purl_response = purl.to_dict()
                purl_response["unresolved_vulnerabilities"] = []
                purl_response["resolved_vulnerabilities"] = []
                purl_response["purl"] = purl_string
            response.append(purl_response)

        return Response(response)

    @action(detail=False, methods=["get"], throttle_scope="vulnerable_packages")
    def all(self, request):
        """
        Return all the vulnerable Package URLs.
        """
        vulnerable_packages = Package.objects.vulnerable().only(*PackageURL._fields).distinct()
        vulnerable_purls = [str(package.purl) for package in vulnerable_packages]
        return Response(vulnerable_purls)


class VulnerabilityFilterSet(filters.FilterSet):
    class Meta:
        model = Vulnerability
        fields = ["vulnerability_id"]


class VulnerabilityViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Lookup for vulnerable packages by vulnerability.
    """

    def get_fixed_packages_qs(self):
        """
        Filter the packages that fixes a vulnerability
        on fields like name, namespace and type.
        """
        package_filter_data = {"packagerelatedvulnerability__fix": True}

        query_params = self.request.query_params
        for field_name in ["name", "namespace", "type"]:
            value = query_params.get(field_name)
            if value:
                package_filter_data[field_name] = value

        return PackageFilterSet(package_filter_data).qs

    def get_queryset(self):
        """
        Assign filtered packages queryset from `get_fixed_packages_qs`
        to a custom attribute `filtered_fixed_packages`
        """
        return Vulnerability.objects.prefetch_related(
            Prefetch(
                "packages",
                queryset=self.get_fixed_packages_qs(),
                to_attr="filtered_fixed_packages",
            )
        )

    serializer_class = VulnerabilitySerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = VulnerabilityFilterSet
    throttle_classes = [StaffUserRateThrottle]
    throttle_scope = "vulnerabilities"


class CPEFilterSet(filters.FilterSet):
    cpe = filters.CharFilter(method="filter_cpe")

    def filter_cpe(self, queryset, name, value):
        cpe = unquote(value)
        return self.queryset.filter(vulnerabilityreference__reference_id__startswith=cpe).distinct()


class CPEViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Lookup for vulnerable packages by CPE.
    """

    queryset = Vulnerability.objects.filter(
        vulnerabilityreference__reference_id__startswith="cpe"
    ).distinct()
    serializer_class = VulnerabilitySerializer
    filter_backends = (filters.DjangoFilterBackend,)
    throttle_classes = [StaffUserRateThrottle]
    filterset_class = CPEFilterSet
    throttle_scope = "cpes"

    @action(detail=False, methods=["post"], throttle_scope="bulk_search_cpes")
    def bulk_search(self, request):
        """
        This endpoint is used to search for vulnerabilities by more than one CPE.
        """
        cpes = request.data.get("cpes", []) or []
        if not cpes or not isinstance(cpes, list):
            return Response(
                status=400,
                data={"Error": "A non-empty 'cpes' list of CPEs is required."},
            )
        for cpe in cpes:
            if not cpe.startswith("cpe"):
                return Response(status=400, data={"Error": f"Invalid CPE: {cpe}"})
        vulnerabilitiesResponse = Vulnerability.objects.filter(
            vulnerabilityreference__reference_id__in=cpes
        ).distinct()
        return Response(
            VulnerabilitySerializer(
                vulnerabilitiesResponse, many=True, context={"request": request}
            ).data
        )


class AliasFilterSet(filters.FilterSet):
    alias = filters.CharFilter(method="filter_alias")

    def filter_alias(self, queryset, name, value):
        alias = unquote(value)
        return self.queryset.filter(aliases__alias__icontains=alias)


class AliasViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Lookup for vulnerabilities by vulnerability aliases such as a CVE.
    """

    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = AliasFilterSet
    throttle_classes = [StaffUserRateThrottle]
    throttle_scope = "aliases"
