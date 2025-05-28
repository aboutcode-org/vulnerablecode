#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#


from django.db.models import Prefetch
from django_filters import rest_framework as filters
from drf_spectacular.utils import OpenApiParameter
from drf_spectacular.utils import extend_schema
from drf_spectacular.utils import extend_schema_view
from packageurl import PackageURL
from rest_framework import mixins
from rest_framework import serializers
from rest_framework import status
from rest_framework import viewsets
from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import action
from rest_framework.permissions import BasePermission
from rest_framework.response import Response
from rest_framework.reverse import reverse

from vulnerabilities.models import CodeFix
from vulnerabilities.models import Package
from vulnerabilities.models import PipelineRun
from vulnerabilities.models import PipelineSchedule
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilitySeverity
from vulnerabilities.models import Weakness


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


class VulnerabilitySeverityV2Serializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilitySeverity
        fields = ["url", "value", "scoring_system", "scoring_elements", "published_at"]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        published_at = data.get("published_at", None)
        if not published_at:
            data.pop("published_at")
        return data


class VulnerabilityV2Serializer(serializers.ModelSerializer):
    aliases = serializers.SerializerMethodField()
    weaknesses = WeaknessV2Serializer(many=True)
    references = VulnerabilityReferenceV2Serializer(many=True, source="vulnerabilityreference_set")
    severities = VulnerabilitySeverityV2Serializer(many=True)
    exploitability = serializers.FloatField(read_only=True)
    weighted_severity = serializers.FloatField(read_only=True)
    risk_score = serializers.FloatField(read_only=True)

    class Meta:
        model = Vulnerability
        fields = [
            "vulnerability_id",
            "aliases",
            "summary",
            "severities",
            "weaknesses",
            "references",
            "exploitability",
            "weighted_severity",
            "risk_score",
        ]

    def get_aliases(self, obj):
        return [alias.alias for alias in obj.aliases.all()]


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


@extend_schema_view(
    list=extend_schema(
        parameters=[
            OpenApiParameter(
                name="vulnerability_id",
                description="Filter by one or more vulnerability IDs",
                required=False,
                type={"type": "array", "items": {"type": "string"}},
                location=OpenApiParameter.QUERY,
            ),
            OpenApiParameter(
                name="alias",
                description="Filter by alias (CVE or other unique identifier)",
                required=False,
                type={"type": "array", "items": {"type": "string"}},
                location=OpenApiParameter.QUERY,
            ),
        ]
    )
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
    risk_score = serializers.FloatField(read_only=True)
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
            "risk_score",
        ]

    def get_affected_by_vulnerabilities(self, obj):
        """
        Return a dictionary with vulnerabilities as keys and their details, including fixed_by_packages.
        """
        result = {}
        request = self.context.get("request")
        for vuln in getattr(obj, "prefetched_affected_vulnerabilities", []):
            fixed_by_package = vuln.fixed_by_packages.first()
            purl = None
            if fixed_by_package:
                purl = fixed_by_package.package_url
            # Get code fixed for a vulnerability
            code_fixes = CodeFix.objects.filter(
                affected_package_vulnerability__vulnerability=vuln
            ).distinct()
            code_fix_urls = [
                reverse("codefix-detail", args=[code_fix.id], request=request)
                for code_fix in code_fixes
            ]

            result[vuln.vulnerability_id] = {
                "vulnerability_id": vuln.vulnerability_id,
                "fixed_by_packages": purl,
                "code_fixes": code_fix_urls,
            }
        return result

    def get_fixing_vulnerabilities(self, obj):
        # Ghost package should not fix any vulnerability.
        if obj.is_ghost:
            return []
        return [vuln.vulnerability_id for vuln in obj.fixing_vulnerabilities.all()]


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


class PackageV2FilterSet(filters.FilterSet):
    affected_by_vulnerability = filters.CharFilter(
        field_name="affected_by_vulnerabilities__vulnerability_id"
    )
    fixing_vulnerability = filters.CharFilter(field_name="fixing_vulnerabilities__vulnerability_id")
    purl = filters.CharFilter(field_name="package_url")


class PackageV2ViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Package.objects.all().prefetch_related(
        Prefetch(
            "affected_by_vulnerabilities",
            queryset=Vulnerability.objects.prefetch_related("fixed_by_packages"),
            to_attr="prefetched_affected_vulnerabilities",
        )
    )
    serializer_class = PackageV2Serializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = PackageV2FilterSet

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
            # Collect only vulnerabilities for packages in the current page
            vulnerabilities = set()
            for package in page:
                vulnerabilities.update(package.affected_by_vulnerabilities.all())
                vulnerabilities.update(package.fixing_vulnerabilities.all())

            # Serialize the vulnerabilities with vulnerability_id as keys
            vulnerability_data = {
                vuln.vulnerability_id: VulnerabilityV2Serializer(vuln).data
                for vuln in vulnerabilities
            }

            # Serialize the current page of packages
            serializer = self.get_serializer(page, many=True)
            data = serializer.data

            # Use 'self.get_paginated_response' to include pagination data
            return self.get_paginated_response(
                {"vulnerabilities": vulnerability_data, "packages": data}
            )

        # If pagination is not applied, collect vulnerabilities for all packages
        vulnerabilities = set()
        for package in queryset:
            vulnerabilities.update(package.affected_by_vulnerabilities.all())
            vulnerabilities.update(package.fixing_vulnerabilities.all())

        vulnerability_data = {
            vuln.vulnerability_id: VulnerabilityV2Serializer(vuln).data for vuln in vulnerabilities
        }

        # Serialize all packages when pagination is not applied
        serializer = self.get_serializer(queryset, many=True)
        data = serializer.data
        return Response({"vulnerabilities": vulnerability_data, "packages": data})

    @extend_schema(
        request=PackageurlListSerializer,
        responses={200: PackageV2Serializer(many=True)},
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

        # Fetch packages matching the provided purls
        packages = Package.objects.for_purls(purls).with_is_vulnerable()

        # Collect vulnerabilities associated with these packages
        vulnerabilities = set()
        for package in packages:
            vulnerabilities.update(package.affected_by_vulnerabilities.all())
            vulnerabilities.update(package.fixing_vulnerabilities.all())

        # Serialize vulnerabilities with vulnerability_id as keys
        vulnerability_data = {
            vuln.vulnerability_id: VulnerabilityV2Serializer(vuln).data for vuln in vulnerabilities
        }

        # Serialize packages
        package_data = PackageV2Serializer(
            packages,
            many=True,
            context={"request": request},
        ).data

        return Response(
            {
                "vulnerabilities": vulnerability_data,
                "packages": package_data,
            }
        )

    @extend_schema(
        request=PackageBulkSearchRequestSerializer,
        responses={200: PackageV2Serializer(many=True)},
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

            packages = query

            # Collect vulnerabilities associated with these packages
            vulnerabilities = set()
            for package in packages:
                vulnerabilities.update(package.affected_by_vulnerabilities.all())
                vulnerabilities.update(package.fixing_vulnerabilities.all())

            vulnerability_data = {
                vuln.vulnerability_id: VulnerabilityV2Serializer(vuln).data
                for vuln in vulnerabilities
            }

            if not purl_only:
                package_data = PackageV2Serializer(
                    packages, many=True, context={"request": request}
                ).data
                return Response(
                    {
                        "vulnerabilities": vulnerability_data,
                        "packages": package_data,
                    }
                )

            # Using order by and distinct because there will be
            # many fully qualified purl for a single plain purl
            vulnerable_purls = query.vulnerable().only("plain_package_url")
            vulnerable_purls = [str(package.plain_package_url) for package in vulnerable_purls]
            return Response(data=vulnerable_purls)

        query = Package.objects.filter(package_url__in=purls).distinct().with_is_vulnerable()
        packages = query

        # Collect vulnerabilities associated with these packages
        vulnerabilities = set()
        for package in packages:
            vulnerabilities.update(package.affected_by_vulnerabilities.all())
            vulnerabilities.update(package.fixing_vulnerabilities.all())

        vulnerability_data = {
            vuln.vulnerability_id: VulnerabilityV2Serializer(vuln).data for vuln in vulnerabilities
        }

        if not purl_only:
            package_data = PackageV2Serializer(
                packages, many=True, context={"request": request}
            ).data
            return Response(
                {
                    "vulnerabilities": vulnerability_data,
                    "packages": package_data,
                }
            )

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
        responses={200: PackageV2Serializer(many=True)},
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
        return Response(PackageV2Serializer(qs, many=True, context={"request": request}).data)


class CodeFixSerializer(serializers.ModelSerializer):
    """
    Serializer for the CodeFix model.
    Provides detailed information about a code fix.
    """

    affected_vulnerability_id = serializers.CharField(
        source="affected_package_vulnerability.vulnerability.vulnerability_id",
        read_only=True,
        help_text="ID of the affected vulnerability.",
    )
    affected_package_purl = serializers.CharField(
        source="affected_package_vulnerability.package.package_url",
        read_only=True,
        help_text="PURL of the affected package.",
    )
    fixed_package_purl = serializers.CharField(
        source="fixed_package_vulnerability.package.package_url",
        read_only=True,
        help_text="PURL of the fixing package (if available).",
    )
    created_at = serializers.DateTimeField(
        format="%Y-%m-%dT%H:%M:%SZ",
        read_only=True,
        help_text="Timestamp when the code fix was created.",
    )
    updated_at = serializers.DateTimeField(
        format="%Y-%m-%dT%H:%M:%SZ",
        read_only=True,
        help_text="Timestamp when the code fix was last updated.",
    )

    class Meta:
        model = CodeFix
        fields = [
            "id",
            "commits",
            "pulls",
            "downloads",
            "patch",
            "affected_vulnerability_id",
            "affected_package_purl",
            "fixed_package_purl",
            "notes",
            "references",
            "is_reviewed",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["created_at", "updated_at"]


class CodeFixViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint that allows viewing CodeFix entries.
    """

    queryset = CodeFix.objects.all()
    serializer_class = CodeFixSerializer

    def get_queryset(self):
        """
        Optionally filter by vulnerability ID.
        """
        queryset = super().get_queryset()
        vulnerability_id = self.request.query_params.get("vulnerability_id")
        if vulnerability_id:
            queryset = queryset.filter(
                affected_package_vulnerability__vulnerability__vulnerability_id=vulnerability_id
            )
        return queryset


class CreateListRetrieveUpdateViewSet(
    mixins.CreateModelMixin,
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    viewsets.GenericViewSet,
):
    """
    A viewset that provides `create`, `list, `retrieve`, and `update` actions.
    To use it, override the class and set the `.queryset` and
    `.serializer_class` attributes.
    """

    pass


class IsAdminWithSessionAuth(BasePermission):
    """Permit only staff users authenticated via session (not token)."""

    def has_permission(self, request, view):
        is_authenticated = request.user and request.user.is_authenticated
        is_staff = request.user and request.user.is_staff
        is_session_auth = isinstance(request.successful_authenticator, SessionAuthentication)

        return is_authenticated and is_staff and is_session_auth


class PipelineRunAPISerializer(serializers.HyperlinkedModelSerializer):
    status = serializers.SerializerMethodField()
    execution_time = serializers.SerializerMethodField()
    log = serializers.SerializerMethodField()

    class Meta:
        model = PipelineRun
        fields = [
            "run_id",
            "status",
            "execution_time",
            "run_start_date",
            "run_end_date",
            "run_exitcode",
            "run_output",
            "created_date",
            "vulnerablecode_version",
            "vulnerablecode_commit",
            "log",
        ]

    def get_status(self, run):
        return run.status

    def get_execution_time(self, run):
        if run.execution_time:
            return round(run.execution_time, 2)

    def get_log(self, run):
        """Return only last 5000 character of log."""
        return run.log[-5000:]


class PipelineScheduleAPISerializer(serializers.HyperlinkedModelSerializer):
    url = serializers.HyperlinkedIdentityField(
        view_name="schedule-detail", lookup_field="pipeline_id"
    )
    latest_run = serializers.SerializerMethodField()
    next_run_date = serializers.SerializerMethodField()

    class Meta:
        model = PipelineSchedule
        fields = [
            "url",
            "pipeline_id",
            "is_active",
            "live_logging",
            "run_interval",
            "execution_timeout",
            "created_date",
            "schedule_work_id",
            "next_run_date",
            "latest_run",
        ]

    def get_next_run_date(self, schedule):
        return schedule.next_run_date

    def get_latest_run(self, schedule):
        if latest := schedule.pipelineruns.first():
            return PipelineRunAPISerializer(latest).data
        return None


class PipelineScheduleCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = PipelineSchedule
        fields = [
            "pipeline_id",
            "is_active",
            "run_interval",
            "live_logging",
            "execution_timeout",
        ]
        extra_kwargs = {
            field: {"initial": PipelineSchedule._meta.get_field(field).get_default()}
            for field in [
                "is_active",
                "run_interval",
                "live_logging",
                "execution_timeout",
            ]
        }


class PipelineScheduleUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = PipelineSchedule
        fields = [
            "is_active",
            "run_interval",
            "live_logging",
            "execution_timeout",
        ]


class PipelineScheduleV2ViewSet(CreateListRetrieveUpdateViewSet):
    queryset = PipelineSchedule.objects.prefetch_related("pipelineruns").all()
    serializer_class = PipelineScheduleAPISerializer
    lookup_field = "pipeline_id"
    lookup_value_regex = r"[\w.]+"

    def get_serializer_class(self):
        if self.action == "create":
            return PipelineScheduleCreateSerializer
        elif self.action == "update":
            return PipelineScheduleUpdateSerializer
        return super().get_serializer_class()

    def get_permissions(self):
        """Restrict addition and modifications to staff users authenticated via session."""
        if self.action not in ["list", "retrieve"]:
            return [IsAdminWithSessionAuth()]
        return super().get_permissions()
