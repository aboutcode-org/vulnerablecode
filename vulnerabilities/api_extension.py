#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from urllib.parse import unquote

from django_filters import rest_framework as filters
from drf_spectacular.utils import extend_schema
from packageurl import PackageURL
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.fields import CharField
from rest_framework.fields import ListField
from rest_framework.fields import SerializerMethodField
from rest_framework.response import Response
from rest_framework.serializers import HyperlinkedModelSerializer
from rest_framework.serializers import ModelSerializer
from rest_framework.serializers import Serializer
from rest_framework.serializers import ValidationError
from rest_framework.throttling import AnonRateThrottle

from vulnerabilities.api import BaseResourceSerializer
from vulnerabilities.models import Exploit
from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.models import Weakness
from vulnerabilities.models import get_purl_query_lookups
from vulnerabilities.throttling import StaffUserRateThrottle


class SerializerExcludeFieldsMixin:
    """
    A Serializer mixin that takes an additional `exclude_fields` argument to
    exclude specific fields from the serialized content.

    Useful for complex serialization where a subclass just needs one less field, like a URL field.
    Inspired by https://www.django-rest-framework.org/api-guide/serializers/#example
    """

    def __init__(self, *args, **kwargs):
        exclude_fields = kwargs.pop("exclude_fields", [])

        super().__init__(*args, **kwargs)

        for field_name in exclude_fields:
            self.fields.pop(field_name)


class ExcludeFieldsSerializerMixin(Serializer):
    """
    A base Serializer with an `exclude_fields` attribute to
    exclude specific fields from the serialized content.

    Useful for complex serialization where a subclass just needs one less field, like a URL field.
    Inspired by https://www.django-rest-framework.org/api-guide/serializers/#example
    """

    exclude_fields = []

    def handle_field(self, obj, field):
        """
        Exlude fields from serialization using the ``exclude_fields`` attribute.
        """
        if field.name in self.exclude_fields:
            return
        super().handle_field(obj, field)


class V2VulnerabilityReferenceSerializer(ModelSerializer):
    reference_url = CharField(source="url")

    class Meta:
        model = VulnerabilityReference
        fields = ("reference_url", "reference_id", "reference_type")


class V2VulnerabilitySeveritySerializer(ModelSerializer):
    score = CharField(source="value")

    class Meta:
        model = VulnerabilitySeverity
        fields = ("url", "score", "scoring_system", "scoring_elements", "published_at")


class V2WeaknessSerializer(ModelSerializer):
    class Meta:
        model = Weakness
        fields = ("cwe",)


class V2WeaknessFullSerializer(ModelSerializer):
    class Meta:
        model = Weakness
        fields = ("cwe", "name", "description")


class V2ExploitSerializer(ModelSerializer):
    class Meta:
        model = Exploit
        fields = [
            "date_added",
            "description",
            "required_action",
            "due_date",
            "notes",
            "known_ransomware_campaign_use",
            "source_date_published",
            "exploit_type",
            "platform",
            "source_date_updated",
            "data_source",
            "source_url",
        ]


class V2VulnerabilitySerializer(ModelSerializer):
    """Vulnerabilities with inlined related objects, but no package."""

    aliases = SerializerMethodField("get_aliases")
    weaknesses = V2WeaknessSerializer(many=True, source="weaknesses_set")
    references = V2VulnerabilityReferenceSerializer(many=True, source="vulnerabilityreference_set")
    exploits = V2ExploitSerializer(many=True, source="weaknesses")
    severities = V2VulnerabilitySeveritySerializer(many=True)

    def get_aliases(self, vulnerability):
        return vulnerability.aliases.only("alias").values_list("alias", flat=True)

    def get_cwes(self, vulnerability):
        return [
            w.cwe for w in vulnerability.weaknesses.only("cwe_id").values_list("cwe_id", flat=True)
        ]

    class Meta:
        model = Vulnerability
        fields = (
            "vulnerability_id",
            "aliases",
            "status",
            "weaknesses",
            "summary",
            "exploits",
            "references",
            "severities",
        )


class V2LinkedVulnerabilitySerializer(V2VulnerabilitySerializer, HyperlinkedModelSerializer):
    """Vulnerabilities with a URL."""

    class Meta:
        model = Vulnerability
        fields = ("url",) + V2VulnerabilitySerializer.Meta.fields


class V2PackageSerializer(BaseResourceSerializer):
    """Package with inlined related vulnerability ids, but no other nested data."""

    purl = CharField(source="package_url")
    next_non_vulnerable_version = SerializerMethodField("get_next_non_vuln_version")
    latest_non_vulnerable_version = SerializerMethodField("get_latest_non_vuln_version")
    affected_by_vulnerabilities = SerializerMethodField("get_affected_by_vulns")
    fixing_vulnerabilities = SerializerMethodField("get_fixing_vulns")

    class Meta:
        model = Package
        fields = (
            "purl",
            "type",
            "namespace",
            "name",
            "version",
            "qualifiers",
            "subpath",
            "next_non_vulnerable_version",
            "latest_non_vulnerable_version",
            "affected_by_vulnerabilities",
            "fixing_vulnerabilities",
        )

    def get_next_non_vuln_version(self, package):
        if next_non_vulnerable := package.fixed_package_details.get("next_non_vulnerable"):
            return next_non_vulnerable.version

    def get_latest_non_vuln_version(self, package):
        if latest_non_vulnerable := package.fixed_package_details.get("latest_non_vulnerable"):
            return latest_non_vulnerable.version

    def get_fixing_vulns(self, package) -> dict:
        return package.fixing_vulnerabilities.only("vulnerability_id").values_list(
            "vulnerability_id"
        )

    def get_affected_by_vulns(self, package) -> dict:
        return package.affected_by_vulnerabilities.only("vulnerability_id").values_list(
            "vulnerability_id"
        )


class V2LinkedPackageSerializer(V2PackageSerializer, HyperlinkedModelSerializer):
    """Serialize package with a URL."""

    class Meta:
        model = Package
        fields = ("url",) + V2PackageSerializer.Meta.fields


class V2PackageurlListSerializer(Serializer):
    """List of purls."""

    purls = ListField(child=CharField(), allow_empty=False, help_text="List of PackageURLs.")


class V2LookupRequestSerializer(Serializer):
    """Single purl."""

    purl = CharField(required=True, help_text="PackageURL string.")


class V2PackageFilterSet(filters.FilterSet):
    purl = filters.CharFilter(method="filter_purl")

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
        ]

    def filter_purl(self, queryset, name, value):
        purl = unquote(value)
        try:
            purl = PackageURL.from_string(purl)

        except ValueError as ve:
            raise ValidationError(
                detail={"error": f'"{purl}" is not a valid Package URL: {ve}'},
            )

        lookups = get_purl_query_lookups(purl)
        return self.queryset.filter(**lookups)


class V2PackageViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Package.objects.all()
    serializer_class = V2LinkedPackageSerializer
    lookup_field = "purl"
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = V2PackageFilterSet
    throttle_classes = [StaffUserRateThrottle, AnonRateThrottle]

    def get_queryset(self):
        return super().get_queryset().with_is_vulnerable().prefetch_related("vulnerabilities")

    @action(detail=False, methods=["get"])
    def all(self, request):
        """
        Return vulnerable package PURLs.
        """
        vulnerable_purls = (
            Package.objects.vulnerable()
            .only("package_url")
            .order_by("package_url")
            .distinct()
            .values_list("package_url")
        )
        return Response(vulnerable_purls)

    @extend_schema(
        request=V2LookupRequestSerializer,
        responses={200: V2PackageSerializer(many=True)},
    )
    @action(
        detail=False,
        methods=["post"],
        serializer_class=V2LookupRequestSerializer,
        filter_backends=[],
    )
    def lookup(self, request):
        """
        Return packages for a single PURL.
        """
        return self._do_lookup(request, field="")

    @extend_schema(
        request=V2PackageurlListSerializer,
        responses={200: V2PackageSerializer(many=True)},
    )
    @action(
        detail=False,
        methods=["post"],
        serializer_class=V2PackageurlListSerializer,
        filter_backends=[],
    )
    def bulk_lookup(self, request):
        """
        Return packages for a list of PURLs.
        """
        return self._do_lookup(request, field="purls")

    def _do_lookup(self, request, field):
        assert field in ("purl", "purls")
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            message = ("A 'purl' or 'purls' list is required.",)
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={"error": serializer.errors, "message": message},
            )
        validated_data = serializer.validated_data
        purls = validated_data.get(field)

        if field == "purl":
            purls = [purls]
        qs = Package.objects.for_purl(purls).with_is_vulnerable()

        return Response(V2PackageSerializer(qs, many=True, context={"request": request}).data)


class V2VulnerabilityFilterSet(filters.FilterSet):
    class Meta:
        model = Vulnerability
        fields = ["vulnerability_id"]


class VulnerabilityViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Lookup for vulnerabilities by id.
    """

    queryset = Vulnerability.objects.all()
    serializer_class = V2VulnerabilitySerializer
    lookup_field = "vulnerability_id"
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = V2VulnerabilityFilterSet
    throttle_classes = [StaffUserRateThrottle, AnonRateThrottle]

    def get_queryset(self):
        """
        Assign filtered packages queryset from `get_fixed_packages_qs`
        to a custom attribute `filtered_fixed_packages`
        """
        return (
            super()
            .get_queryset()
            .prefetch_related(
                "weaknesses",
                "severities",
                # "exploits",
            )
        )


class CPEFilterSet(filters.FilterSet):
    cpe = filters.CharFilter(method="filter_cpe")

    def filter_cpe(self, queryset, name, value):
        cpe = unquote(value)
        return self.queryset.filter(vulnerabilityreference__reference_id__startswith=cpe).distinct()


class CPEViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Search for vulnerabilities by CPE (https://nvd.nist.gov/products/cpe)
    """

    queryset = Vulnerability.objects.filter(
        vulnerabilityreference__reference_id__startswith="cpe"
    ).distinct()
    serializer_class = V2VulnerabilitySerializer
    filter_backends = (filters.DjangoFilterBackend,)
    throttle_classes = [StaffUserRateThrottle, AnonRateThrottle]
    filterset_class = CPEFilterSet

    @action(detail=False, methods=["post"])
    def bulk_search(self, request):
        """
        Search for vulnerabilities referencing any of list of CPEs.
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
        qs = Vulnerability.objects.filter(vulnerabilityreference__reference_id__in=cpes).distinct()
        return Response(V2VulnerabilitySerializer(qs, many=True, context={"request": request}).data)


class AliasFilterSet(filters.FilterSet):
    alias = filters.CharFilter(method="filter_alias")

    def filter_alias(self, queryset, name, value):
        alias = unquote(value)
        return self.queryset.filter(aliases__alias__icontains=alias)


class AliasViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Lookup for vulnerabilities by vulnerability aliases such as a CVE
    (https://nvd.nist.gov/general/cve-process).
    """

    queryset = Vulnerability.objects.all()
    serializer_class = V2VulnerabilitySerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = AliasFilterSet
    throttle_classes = [StaffUserRateThrottle, AnonRateThrottle]
