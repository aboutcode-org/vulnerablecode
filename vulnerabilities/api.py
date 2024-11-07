#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from urllib.parse import unquote

from cvss.exceptions import CVSS2MalformedError
from cvss.exceptions import CVSS3MalformedError
from cvss.exceptions import CVSS4MalformedError
from django.db.models import Prefetch
from django_filters import rest_framework as filters
from drf_spectacular.utils import extend_schema
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

from vulnerabilities.models import Alias
from vulnerabilities.models import Exploit
from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.models import Weakness
from vulnerabilities.models import get_purl_query_lookups
from vulnerabilities.severity_systems import EPSS
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.throttling import StaffUserRateThrottle
from vulnerabilities.utils import get_severity_range


class VulnerabilitySeveritySerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilitySeverity
        fields = ["value", "scoring_system", "scoring_elements", "published_at"]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        published_at = data.get("published_at", None)
        if not published_at:
            data.pop("published_at")
        return data


class VulnerabilityReferenceSerializer(serializers.ModelSerializer):
    scores = VulnerabilitySeveritySerializer(many=True, source="vulnerabilityseverity_set")
    reference_url = serializers.CharField(source="url")

    class Meta:
        model = VulnerabilityReference
        fields = ["reference_url", "reference_id", "reference_type", "scores", "url"]


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


class VulnVulnIDSerializer(serializers.Serializer):
    """
    Serializer for the series of vulnerability IDs.
    """

    vulnerability = serializers.CharField(source="vulnerability_id")

    class Meta:
        fields = ["vulnerability"]


class MinimalPackageSerializer(BaseResourceSerializer):
    """
    Used for nesting inside vulnerability focused APIs.
    """

    affected_by_vulnerabilities = VulnVulnIDSerializer(source="affecting_vulns", many=True)

    purl = serializers.CharField(source="package_url")

    is_vulnerable = serializers.BooleanField()

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

    fixed_packages = MinimalPackageSerializer(
        many=True, source="filtered_fixed_packages", read_only=True
    )

    references = VulnerabilityReferenceSerializer(many=True, source="vulnerabilityreference_set")

    aliases = serializers.SerializerMethodField()

    def get_aliases(self, obj):
        # Assuming `obj.aliases` is a queryset of `Alias` objects
        return [alias.alias for alias in obj.aliases.all()]

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


class ExploitSerializer(serializers.ModelSerializer):
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


class VulnerabilitySerializer(BaseResourceSerializer):
    fixed_packages = MinimalPackageSerializer(
        many=True, source="filtered_fixed_packages", read_only=True
    )
    affected_packages = MinimalPackageSerializer(many=True, read_only=True)

    references = VulnerabilityReferenceSerializer(many=True, source="vulnerabilityreference_set")
    aliases = AliasSerializer(many=True, source="alias")
    exploits = ExploitSerializer(many=True, read_only=True)
    weaknesses = WeaknessSerializer(many=True)
    severity_range_score = serializers.SerializerMethodField()

    def to_representation(self, instance):
        data = super().to_representation(instance)

        weaknesses = data.get("weaknesses", [])
        data["weaknesses"] = [weakness for weakness in weaknesses if weakness is not None]

        return data

    def get_severity_range_score(self, instance):
        severity_vectors = []
        severity_values = set()
        for s in instance.severities:
            if s.scoring_system == EPSS.identifier:
                continue

            if s.scoring_elements and s.scoring_system in SCORING_SYSTEMS:
                try:
                    vector_values = SCORING_SYSTEMS[s.scoring_system].get(s.scoring_elements)
                    severity_vectors.append(vector_values)
                except (
                    CVSS2MalformedError,
                    CVSS3MalformedError,
                    CVSS4MalformedError,
                    NotImplementedError,
                ):
                    pass

            if s.value:
                severity_values.add(s.value)
        severity_range = get_severity_range(severity_values)
        return severity_range

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
            "exploits",
            "severity_range_score",
        ]


class PackageSerializer(BaseResourceSerializer):
    """
    Lookup software package using Package URLs
    """

    next_non_vulnerable_version = serializers.CharField(read_only=True)
    latest_non_vulnerable_version = serializers.CharField(read_only=True)

    purl = serializers.CharField(source="package_url")

    affected_by_vulnerabilities = serializers.SerializerMethodField("get_affected_vulnerabilities")

    fixing_vulnerabilities = serializers.SerializerMethodField("get_fixing_vulnerabilities")

    qualifiers = serializers.SerializerMethodField()

    is_vulnerable = serializers.BooleanField()

    def get_qualifiers(self, package):
        return normalize_qualifiers(package.qualifiers, encode=False)

    def get_fixed_packages(self, package):
        """
        Return a queryset of all packages that fix a vulnerability with
        same type, namespace, name, subpath and qualifiers of the `package`
        """
        return (
            Package.objects.filter(
                name=package.name,
                namespace=package.namespace,
                type=package.type,
                qualifiers=package.qualifiers,
                subpath=package.subpath,
                fixingpackagerelatedvulnerability__isnull=False,
            )
            .with_is_vulnerable()
            .distinct()
        )

    def get_vulnerabilities_for_a_package(self, package, fix) -> dict:
        """
        Return a mapping of vulnerabilities data related to the given `package`.
        Return vulnerabilities that affect the `package` if given `fix` flag is False,
        otherwise return vulnerabilities fixed by the `package`.
        """
        fixed_packages = self.get_fixed_packages(package=package)
        if fix:
            qs = package.affected_by_vulnerabilities.all()
        else:
            qs = package.fixing_vulnerabilities.all()
        qs = qs.prefetch_related(
            Prefetch(
                "fixed_by_packages",
                queryset=fixed_packages,
                to_attr="filtered_fixed_packages",
            )
        )
        return VulnSerializerRefsAndSummary(
            instance=qs,
            many=True,
            context={"request": self.context["request"]},
        ).data

    def get_fixing_vulnerabilities(self, package) -> dict:
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
            "is_vulnerable",
            "next_non_vulnerable_version",
            "latest_non_vulnerable_version",
            "affected_by_vulnerabilities",
            "fixing_vulnerabilities",
            "risk_score",
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

    def get_queryset(self):
        return super().get_queryset().with_is_vulnerable()

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
                .with_is_vulnerable()
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

        query = Package.objects.filter(package_url__in=purls).distinct().with_is_vulnerable()

        if not purl_only:
            return Response(PackageSerializer(query, many=True, context={"request": request}).data)

        vulnerable_purls = query.vulnerable().only("package_url")
        vulnerable_purls = [str(package.package_url) for package in vulnerable_purls]
        return Response(data=vulnerable_purls)

    @action(detail=False, methods=["get"])
    def all(self, request):
        """
        Return a list of Package URLs of vulnerable packages.
        """
        vulnerable_purls = (
            Package.objects.vulnerable()
            .only("package_url")
            .order_by("package_url")
            .distinct()
            .values_list("package_url", flat=True)
        )
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

        qs = self.get_queryset().for_purls([purl]).with_is_vulnerable()
        return Response(PackageSerializer(qs, many=True, context={"request": request}).data)

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
                Package.objects.for_purls(purls).with_is_vulnerable(),
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

    queryset = Vulnerability.objects.all()

    def get_fixed_packages_qs(self):
        """
        Filter the packages that fixes a vulnerability
        on fields like name, namespace and type.
        """
        return (
            self.get_packages_qs()
            .filter(fixingpackagerelatedvulnerability__isnull=False)
            .with_is_vulnerable()
        )

    def get_packages_qs(self):
        """
        Filter the packages on type, namespace and name.
        """
        query_params = self.request.query_params
        package_filter_data = {}
        for field_name in ("type", "namespace", "name"):
            if value := query_params.get(field_name):
                package_filter_data[field_name] = value

        return PackageFilterSet(package_filter_data).qs.with_is_vulnerable()

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
                Prefetch(
                    "fixed_by_packages",
                    queryset=self.get_fixed_packages_qs(),
                    to_attr="filtered_fixed_packages",
                ),
            )
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


class CPEViewSet(VulnerabilityViewSet):
    """Lookup for vulnerabilities by CPE (https://nvd.nist.gov/products/cpe)"""

    queryset = Vulnerability.objects.filter(
        vulnerabilityreference__reference_id__startswith="cpe"
    ).distinct()

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


class AliasViewSet(VulnerabilityViewSet):
    """
    Lookup for vulnerabilities by vulnerability aliases such as a CVE
    (https://nvd.nist.gov/general/cve-process).
    """

    filterset_class = AliasFilterSet


class WeaknessV2Serializer(serializers.ModelSerializer):
    cwe_id = serializers.CharField()
    name = serializers.CharField()
    description = serializers.CharField()

    class Meta:
        model = Weakness
        fields = ["cwe_id", "name", "description"]


class VulnerabilityReferenceV2Serializer(serializers.ModelSerializer):
    url = serializers.CharField()
    reference_type = serializers.CharField()
    reference_id = serializers.CharField()

    class Meta:
        model = VulnerabilityReference
        fields = ["url", "reference_type", "reference_id"]


class VulnerabilityV2Serializer(BaseResourceSerializer):
    aliases = serializers.SerializerMethodField()
    weaknesses = WeaknessV2Serializer(many=True)
    references = VulnerabilityReferenceV2Serializer(many=True, source="vulnerabilityreference_set")
    severities = VulnerabilitySeveritySerializer(many=True)

    class Meta:
        model = Vulnerability
        fields = [
            "vulnerability_id",
            "aliases",
            "summary",
            "severities",
            "weaknesses",
            "references",
        ]

    def get_aliases(self, obj):
        return [alias.alias for alias in obj.aliases.all()]

    def get_severities(self, obj):
        return obj.severities


class VulnerabilityListSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField()

    class Meta:
        model = Vulnerability
        fields = ["vulnerability_id", "url"]

    def get_url(self, obj):
        request = self.context.get("request")
        return reverse(
            "vulnerability-v2-detail",
            kwargs={"vulnerability_id": obj.vulnerability_id},
            request=request,
        )


class VulnerabilityV2ViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilityV2Serializer
    lookup_field = "vulnerability_id"

    def get_queryset(self):
        queryset = super().get_queryset()
        vulnerability_ids = self.request.query_params.getlist("vulnerability_id")
        aliases = self.request.query_params.getlist("alias")

        if vulnerability_ids:
            queryset = queryset.filter(vulnerability_id__in=vulnerability_ids)

        if aliases:
            queryset = queryset.filter(aliases__alias__in=aliases).distinct()

        return queryset

    def get_serializer_class(self):
        if self.action == "list":
            return VulnerabilityListSerializer
        return super().get_serializer_class()

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        vulnerability_ids = request.query_params.getlist("vulnerability_id")

        # If exactly one vulnerability_id is provided, return the serialized data
        if len(vulnerability_ids) == 1:
            try:
                vulnerability = queryset.get(vulnerability_id=vulnerability_ids[0])
                serializer = self.get_serializer(vulnerability)
                return Response(serializer.data)
            except Vulnerability.DoesNotExist:
                return Response({"detail": "Not found."}, status=404)

        # Otherwise, return a dictionary of vulnerabilities keyed by vulnerability_id
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            data = serializer.data
            vulnerabilities = {item["vulnerability_id"]: item for item in data}
            return self.get_paginated_response({"vulnerabilities": vulnerabilities})

        serializer = self.get_serializer(queryset, many=True)
        data = serializer.data
        vulnerabilities = {item["vulnerability_id"]: item for item in data}
        return Response({"vulnerabilities": vulnerabilities})


class PackageV2Serializer(serializers.ModelSerializer):
    purl = serializers.CharField(source="package_url")
    affected_by_vulnerabilities = serializers.SerializerMethodField()
    fixing_vulnerabilities = serializers.SerializerMethodField()
    next_non_vulnerable_version = serializers.CharField(read_only=True)
    latest_non_vulnerable_version = serializers.CharField(read_only=True)

    class Meta:
        model = Package
        fields = [
            "purl",
            "affected_by_vulnerabilities",
            "fixing_vulnerabilities",
            "next_non_vulnerable_version",
            "latest_non_vulnerable_version",
        ]

    def get_affected_by_vulnerabilities(self, obj):
        return [vuln.vulnerability_id for vuln in obj.affected_by_vulnerabilities.all()]

    def get_fixing_vulnerabilities(self, obj):
        return [vuln.vulnerability_id for vuln in obj.fixing_vulnerabilities.all()]


class PackageV2ViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Package.objects.all()
    serializer_class = PackageV2Serializer

    def get_queryset(self):
        queryset = super().get_queryset()
        package_purls = self.request.query_params.getlist("purl")
        affected_by_vulnerability = self.request.query_params.get("affected_by_vulnerability")
        fixing_vulnerability = self.request.query_params.get("fixing_vulnerability")

        if package_purls:
            queryset = queryset.filter(package_url__in=package_purls)
        if affected_by_vulnerability:
            queryset = queryset.filter(
                affected_by_vulnerabilities__vulnerability_id=affected_by_vulnerability
            )
        if fixing_vulnerability:
            queryset = queryset.filter(
                fixing_vulnerabilities__vulnerability_id=fixing_vulnerability
            )
        return queryset.with_is_vulnerable()

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        # Apply pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            data = serializer.data
            # Use 'self.get_paginated_response' to include pagination data
            return self.get_paginated_response({"purls": data})

        # If pagination is not applied
        serializer = self.get_serializer(queryset, many=True)
        data = serializer.data
        return Response({"purls": data})
