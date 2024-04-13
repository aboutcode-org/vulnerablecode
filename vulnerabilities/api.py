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
from drf_spectacular.utils import extend_schema
from drf_spectacular.utils import inline_serializer
from packageurl import PackageURL
from packageurl import normalize_qualifiers
from rest_framework import serializers
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.throttling import AnonRateThrottle
from rest_framework.throttling import UserRateThrottle

from vulnerabilities.models import Advisory
from vulnerabilities.models import Alias
from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.models import Weakness
from vulnerabilities.models import get_purl_query_lookups
from vulnerabilities.throttling import StaffUserRateThrottle


class VulnerabilitySeveritySerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilitySeverity
        fields = ["value", "scoring_system", "scoring_elements"]


class VulnerabilityReferenceSerializer(serializers.ModelSerializer):
    scores = VulnerabilitySeveritySerializer(many=True, source="vulnerabilityseverity_set")
    reference_url = serializers.CharField(source="url")

    class Meta:
        model = VulnerabilityReference
        fields = ["reference_url", "reference_id", "scores", "url"]


class BaseResourceSerializer(serializers.HyperlinkedModelSerializer):
    """
    Base serializer containing common methods.
    """

    def get_fields(self):
        fields = super().get_fields()
        fields["resource_url"] = serializers.SerializerMethodField(method_name="get_resource_url")
        return fields

    def get_resource_url(self, instance):
        """
        Return the instance fully qualified URL including the schema and domain.

        Usage:
            resource_url = serializers.SerializerMethodField()
        """
        resource_url = instance.get_absolute_url()

        if request := self.context.get("request", None):
            return request.build_absolute_uri(location=resource_url)

        return resource_url


class MinimalPackageSerializer(BaseResourceSerializer):
    """
    Used for nesting inside vulnerability focused APIs.
    """

    def get_affected_vulnerabilities(self, package):
        parent_affected_vulnerabilities = package.fixed_package_details.get("vulnerabilities") or []

        affected_vulnerabilities = [
            self.get_vulnerability(vuln) for vuln in parent_affected_vulnerabilities
        ]

        return affected_vulnerabilities

    def get_vulnerability(self, vuln):
        affected_vulnerability = {}

        vulnerability = vuln.get("vulnerability")
        if vulnerability:
            affected_vulnerability["vulnerability"] = vulnerability.vulnerability_id
            return affected_vulnerability

    affected_by_vulnerabilities = serializers.SerializerMethodField("get_affected_vulnerabilities")

    purl = serializers.CharField(source="package_url")

    class Meta:
        model = Package
        fields = ["url", "purl", "is_vulnerable", "affected_by_vulnerabilities"]


class MinimalVulnerabilitySerializer(BaseResourceSerializer):
    """
    Lookup vulnerabilities by aliases (such as a CVE).
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


class VulnSerializerRefsAndSummary(BaseResourceSerializer):
    """
    Lookup vulnerabilities references by aliases (such as a CVE).
    """

    def to_representation(self, instance):
        data = super().to_representation(instance)
        aliases = [alias["alias"] for alias in data["aliases"]]
        data["aliases"] = aliases
        return data

    fixed_packages = MinimalPackageSerializer(
        many=True, source="filtered_fixed_packages", read_only=True
    )

    references = VulnerabilityReferenceSerializer(many=True, source="vulnerabilityreference_set")
    aliases = AliasSerializer(many=True, source="alias")

    class Meta:
        model = Vulnerability
        fields = ["url", "vulnerability_id", "summary", "references", "fixed_packages", "aliases"]


class WeaknessSerializer(serializers.HyperlinkedModelSerializer):
    """
    Used for nesting inside weakness focused APIs.
    """

    class Meta:
        model = Weakness
        fields = ["cwe_id", "name", "description"]

    def to_representation(self, instance):
        """
        Override to include 'weakness' only if it is not None.
        """
        representation = super().to_representation(instance)
        if instance.weakness is None:
            return None
        return representation


class VulnerabilitySerializer(BaseResourceSerializer):
    fixed_packages = MinimalPackageSerializer(
        many=True, source="filtered_fixed_packages", read_only=True
    )
    affected_packages = MinimalPackageSerializer(many=True, read_only=True)

    references = VulnerabilityReferenceSerializer(many=True, source="vulnerabilityreference_set")
    aliases = AliasSerializer(many=True, source="alias")
    weaknesses = WeaknessSerializer(many=True)

    def to_representation(self, instance):
        data = super().to_representation(instance)

        weaknesses = data.get("weaknesses", [])
        data["weaknesses"] = [weakness for weakness in weaknesses if weakness is not None]
        alias_queryset = instance.aliases.all()
        data["advisory"] = []
        for itr in alias_queryset:
            advisory_objects = Advisory.objects.filter(aliases=[itr.alias])
            for advisory_object in advisory_objects:
                data["advisory"].append(
                    {
                        "unique_content_id": advisory_object.unique_content_id,
                        "url": advisory_object.url,
                        "summary": advisory_object.summary,
                        "date_collected": advisory_object.date_collected,
                        "created_by": advisory_object.created_by,
                    }
                )
                

        return data

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
            "weaknesses",
        ]


class PackageSerializer(BaseResourceSerializer):
    """
    Lookup software package using Package URLs
    """

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["qualifiers"] = normalize_qualifiers(data["qualifiers"], encode=False)

        return data

    next_non_vulnerable_version = serializers.SerializerMethodField("get_next_non_vulnerable")

    def get_next_non_vulnerable(self, package):
        next_non_vulnerable = package.fixed_package_details.get("next_non_vulnerable", None)
        if next_non_vulnerable:
            return next_non_vulnerable.version

    latest_non_vulnerable_version = serializers.SerializerMethodField("get_latest_non_vulnerable")

    def get_latest_non_vulnerable(self, package):
        latest_non_vulnerable = package.fixed_package_details.get("latest_non_vulnerable", None)
        if latest_non_vulnerable:
            return latest_non_vulnerable.version

    purl = serializers.CharField(source="package_url")

    affected_by_vulnerabilities = serializers.SerializerMethodField("get_affected_vulnerabilities")

    fixing_vulnerabilities = serializers.SerializerMethodField("get_fixed_vulnerabilities")

    def get_fixed_packages(self, package):
        """
        Return a queryset of all packages that fix a vulnerability with
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
        Return vulnerabilities that affect the `package` if given `fix` flag is False,
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
        Return a mapping of vulnerabilities that affect the given `package` (including packages that
        fix each vulnerability and whose version is greater than the `package` version).
        """
        excluded_purls = []
        package_vulnerabilities = self.get_vulnerabilities_for_a_package(package=package, fix=False)

        for vuln in package_vulnerabilities:
            for pkg in vuln["fixed_packages"]:
                real_purl = PackageURL.from_string(pkg["purl"])
                if package.version_class(real_purl.version) <= package.current_version:
                    excluded_purls.append(pkg)

            vuln["fixed_packages"] = [
                pkg for pkg in vuln["fixed_packages"] if pkg not in excluded_purls
            ]

        return package_vulnerabilities

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
            "next_non_vulnerable_version",
            "latest_non_vulnerable_version",
            "affected_by_vulnerabilities",
            "fixing_vulnerabilities",
        ]


class PackageFilterSet(filters.FilterSet):
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


class PackageurlListSerializer(serializers.Serializer):
    purls = serializers.ListField(
        child=serializers.CharField(),
        allow_empty=False,
        help_text="List of PackageURL strings in canonical form.",
    )


class PackageBulkSearchRequestSerializer(PackageurlListSerializer):
    purl_only = serializers.BooleanField(required=False, default=False)
    plain_purl = serializers.BooleanField(required=False, default=False)


class LookupRequestSerializer(serializers.Serializer):
    purl = serializers.CharField(
        required=True,
        help_text="PackageURL strings in canonical form.",
    )


class PackageViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Lookup for vulnerable packages by Package URL.
    """

    queryset = Package.objects.all()
    serializer_class = PackageSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = PackageFilterSet
    throttle_classes = [StaffUserRateThrottle, AnonRateThrottle]

    @extend_schema(
        request=PackageBulkSearchRequestSerializer,
        responses={200: PackageSerializer(many=True)},
    )
    @action(
        detail=False,
        methods=["post"],
        serializer_class=PackageBulkSearchRequestSerializer,
        filter_backends=[],
        pagination_class=None,
    )
    def bulk_search(self, request):
        """
        Lookup for vulnerable packages using many Package URLs at once.
        """
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "error": serializer.errors,
                    "message": "A non-empty 'purls' list of PURLs is required.",
                },
            )
        validated_data = serializer.validated_data
        purls = validated_data.get("purls")
        purl_only = validated_data.get("purl_only", False)
        plain_purl = validated_data.get("plain_purl", False)

        if plain_purl:
            purl_objects = [PackageURL.from_string(purl) for purl in purls]
            plain_purl_objects = [
                PackageURL(
                    type=purl.type,
                    namespace=purl.namespace,
                    name=purl.name,
                    version=purl.version,
                )
                for purl in purl_objects
            ]
            plain_purls = [str(purl) for purl in plain_purl_objects]

            query = (
                Package.objects.filter(plain_package_url__in=plain_purls)
                .order_by("plain_package_url")
                .distinct("plain_package_url")
            )

            if not purl_only:
                return Response(
                    PackageSerializer(query, many=True, context={"request": request}).data
                )

            # using order by and distinct because there will be
            # many fully qualified purl for a single plain purl
            vulnerable_purls = query.vulnerable().only("plain_package_url")
            vulnerable_purls = [str(package.plain_package_url) for package in vulnerable_purls]
            return Response(data=vulnerable_purls)

        query = Package.objects.filter(package_url__in=purls).distinct()

        if not purl_only:
            return Response(PackageSerializer(query, many=True, context={"request": request}).data)

        vulnerable_purls = query.vulnerable().only("package_url")
        vulnerable_purls = [str(package.package_url) for package in vulnerable_purls]
        return Response(data=vulnerable_purls)

    @action(detail=False, methods=["get"])
    def all(self, request):
        """
        Return the Package URLs of all packages known to be vulnerable.
        """
        vulnerable_packages = Package.objects.vulnerable().only("package_url").distinct()
        vulnerable_purls = [str(package.package_url) for package in vulnerable_packages]
        return Response(vulnerable_purls)

    @extend_schema(
        request=LookupRequestSerializer,
        responses={200: PackageSerializer(many=True)},
    )
    @action(
        detail=False,
        methods=["post"],
        serializer_class=LookupRequestSerializer,
        filter_backends=[],
        pagination_class=None,
    )
    def lookup(self, request):
        """
        Return the response for exact PackageURL requested for.
        """
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "error": serializer.errors,
                    "message": "A 'purl' is required.",
                },
            )
        validated_data = serializer.validated_data
        purl = validated_data.get("purl")

        return Response(
            PackageSerializer(
                Package.objects.for_purls([purl]), many=True, context={"request": request}
            ).data
        )

    @extend_schema(
        request=PackageurlListSerializer,
        responses={200: PackageSerializer(many=True)},
    )
    @action(
        detail=False,
        methods=["post"],
        serializer_class=PackageurlListSerializer,
        filter_backends=[],
        pagination_class=None,
    )
    def bulk_lookup(self, request):
        """
        Return the response for exact PackageURLs requested for.
        """
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return Response(
                status=status.HTTP_400_BAD_REQUEST,
                data={
                    "error": serializer.errors,
                    "message": "A non-empty 'purls' list of PURLs is required.",
                },
            )
        validated_data = serializer.validated_data
        purls = validated_data.get("purls")

        return Response(
            PackageSerializer(
                Package.objects.for_purls(purls),
                many=True,
                context={"request": request},
            ).data
        )


class VulnerabilityFilterSet(filters.FilterSet):
    class Meta:
        model = Vulnerability
        fields = ["vulnerability_id"]


class VulnerabilityViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Lookup for vulnerabilities affecting packages.
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
            "weaknesses",
            Prefetch(
                "packages",
                queryset=self.get_fixed_packages_qs(),
                to_attr="filtered_fixed_packages",
            ),
        )

    serializer_class = VulnerabilitySerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = VulnerabilityFilterSet
    throttle_classes = [StaffUserRateThrottle, AnonRateThrottle]


class CPEFilterSet(filters.FilterSet):
    cpe = filters.CharFilter(method="filter_cpe")

    def filter_cpe(self, queryset, name, value):
        cpe = unquote(value)
        return self.queryset.filter(vulnerabilityreference__reference_id__startswith=cpe).distinct()


class CPEViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Lookup for vulnerabilities by CPE (https://nvd.nist.gov/products/cpe)
    """

    queryset = Vulnerability.objects.filter(
        vulnerabilityreference__reference_id__startswith="cpe"
    ).distinct()
    serializer_class = VulnerabilitySerializer
    filter_backends = (filters.DjangoFilterBackend,)
    throttle_classes = [StaffUserRateThrottle, AnonRateThrottle]
    filterset_class = CPEFilterSet

    @action(detail=False, methods=["post"])
    def bulk_search(self, request):
        """
        Lookup for vulnerabilities using many CPEs at once.
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
    Lookup for vulnerabilities by vulnerability aliases such as a CVE
    (https://nvd.nist.gov/general/cve-process).
    """

    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = AliasFilterSet
    throttle_classes = [StaffUserRateThrottle, AnonRateThrottle]
