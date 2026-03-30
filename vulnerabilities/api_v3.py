#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from urllib.parse import urlencode

from django.db.models import Exists
from django.db.models import OuterRef
from django.db.models import Prefetch
from django_filters import rest_framework as filters
from packageurl import PackageURL
from rest_framework import serializers
from rest_framework import viewsets
from rest_framework.reverse import reverse
from rest_framework.throttling import AnonRateThrottle

from vulnerabilities.models import AdvisoryReference
from vulnerabilities.models import AdvisorySet
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import AdvisoryWeakness
from vulnerabilities.models import ImpactedPackageAffecting
from vulnerabilities.models import PackageV2
from vulnerabilities.throttling import PermissionBasedUserRateThrottle
from vulnerabilities.utils import TYPES_WITH_MULTIPLE_IMPORTERS
from vulnerabilities.utils import get_advisories_from_groups
from vulnerabilities.utils import merge_and_save_grouped_advisories


class PackageQuerySerializer(serializers.Serializer):
    purls = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        default=list,
    )
    details = serializers.BooleanField(default=False)
    approximate = serializers.BooleanField(default=False)

    def validate(self, data):
        if not data["purls"]:
            if data["details"] or data["approximate"]:
                raise serializers.ValidationError(
                    "details and approximate must be false when purls is empty"
                )
        return data


class AdvisoryQuerySerializer(serializers.Serializer):
    purls = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        default=list,
    )

    def validate(self, data):
        if not data["purls"]:
            raise serializers.ValidationError("purls is required")
        return data


class AdvisoryReferenceSerializer(serializers.ModelSerializer):
    url = serializers.CharField()
    reference_type = serializers.CharField()
    reference_id = serializers.CharField()

    class Meta:
        model = AdvisoryReference
        fields = ["url", "reference_type", "reference_id"]


class AdvisorySeveritySerializer(serializers.ModelSerializer):
    class Meta:
        model = AdvisorySeverity
        fields = ["url", "value", "scoring_system", "scoring_elements", "published_at"]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        published_at = data.get("published_at", None)
        if not published_at:
            data.pop("published_at")
        return data


class AdvisoryWeaknessSerializer(serializers.ModelSerializer):
    cwe_id = serializers.CharField()
    name = serializers.CharField()
    description = serializers.CharField()

    class Meta:
        model = AdvisoryWeakness
        fields = ["cwe_id", "name", "description"]


class AdvisoryV3Serializer(serializers.ModelSerializer):
    aliases = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field="alias",
    )
    weaknesses = AdvisoryWeaknessSerializer(many=True)
    references = AdvisoryReferenceSerializer(many=True)
    severities = AdvisorySeveritySerializer(many=True)
    advisory_id = serializers.CharField(source="avid", read_only=True)
    related_ssvc_trees = serializers.SerializerMethodField()

    def get_related_ssvc_trees(self, obj):
        seen = set()
        result = []

        all_ssvcs = list(obj.related_ssvcs.all()) + list(obj.source_ssvcs.all())

        for ssvc in all_ssvcs:
            key = (ssvc.vector, ssvc.source_advisory_id)
            if key in seen:
                continue
            seen.add(key)

            result.append(
                {
                    "vector": ssvc.vector,
                    "decision": ssvc.decision,
                    "options": ssvc.options,
                    "source_url": ssvc.source_advisory.url,
                }
            )

        return result

    class Meta:
        model = AdvisoryV2
        fields = [
            "advisory_id",
            "url",
            "aliases",
            "summary",
            "severities",
            "weaknesses",
            "references",
            "exploitability",
            "weighted_severity",
            "risk_score",
            "related_ssvc_trees",
        ]

    def get_aliases(self, obj):
        return [alias.alias for alias in obj.aliases.all()]


class PackageV3Serializer(serializers.ModelSerializer):
    purl = serializers.CharField(source="package_url")
    risk_score = serializers.FloatField(read_only=True)
    affected_by_vulnerabilities = serializers.SerializerMethodField()
    affected_by_vulnerabilities_url = serializers.SerializerMethodField()
    fixing_vulnerabilities = serializers.SerializerMethodField()
    fixing_vulnerabilities_url = serializers.SerializerMethodField()
    next_non_vulnerable_version = serializers.SerializerMethodField()
    latest_non_vulnerable_version = serializers.SerializerMethodField()

    class Meta:
        model = PackageV2
        fields = [
            "purl",
            "affected_by_vulnerabilities",
            "affected_by_vulnerabilities_url",
            "fixing_vulnerabilities",
            "fixing_vulnerabilities_url",
            "next_non_vulnerable_version",
            "latest_non_vulnerable_version",
            "risk_score",
        ]

    def to_representation(self, instance):
        data = super().to_representation(instance)

        if data.get("affected_by_vulnerabilities") is None:
            data.pop("affected_by_vulnerabilities", None)
        else:
            data.pop("affected_by_vulnerabilities_url", None)

        if data.get("fixing_vulnerabilities") is None:
            data.pop("fixing_vulnerabilities", None)
        else:
            data.pop("fixing_vulnerabilities_url", None)

        return data

    def get_affected_by_vulnerabilities_url(self, obj):
        request = self.context.get("request")
        if not request:
            return None

        base = reverse("affected-by-advisories-list")
        url = request.build_absolute_uri(base)

        return f"{url}?{urlencode({'purl': obj.package_url})}"

    def get_fixing_vulnerabilities_url(self, obj):
        request = self.context.get("request")
        if not request:
            return None

        base = reverse("fixing-advisories-list")
        url = request.build_absolute_uri(base)

        return f"{url}?{urlencode({'purl': obj.package_url})}"

    def get_affected_by_vulnerabilities(self, package):
        """Return a dictionary with advisory as keys and their details, including fixed_by_packages."""
        advisories_qs = AdvisoryV2.objects.latest_affecting_advisories_for_purl(package.package_url)

        advisories = []

        is_grouped = AdvisorySet.objects.filter(package=package, relation_type="affecting").exists()

        if is_grouped:
            affected_by_advisories_qs = AdvisorySet.objects.filter(
                package=package, relation_type="affecting"
            ).select_related("primary_advisory")

            affected_groups = [
                (list(adv.aliases.all()), adv.primary_advisory, "")
                for adv in affected_by_advisories_qs
            ]

            advisories = get_advisories_from_groups(affected_groups)
            return self.return_advisories_data(package, advisories_qs, advisories)

        if package.type in TYPES_WITH_MULTIPLE_IMPORTERS:
            advisories_qs = advisories_qs.prefetch_related(
                "aliases",
                "impacted_packages__affecting_packages",
                "impacted_packages__fixed_by_packages",
            )
            advisories = merge_and_save_grouped_advisories(package, advisories_qs, "affecting")
            return self.return_advisories_data(package, advisories_qs, advisories)

        advisories_ids = advisories_qs.only("id")

        advisories_ids = list(advisories_ids[:101])
        if len(advisories_ids) > 100:
            return None

        advisory_by_avid = {adv.avid: adv for adv in advisories_qs}
        avids = advisory_by_avid.keys()

        impacts = (
            package.affected_in_impacts.filter(advisory__avid__in=avids)
            .select_related("advisory")
            .prefetch_related("fixed_by_packages")
        )

        impact_by_avid = {impact.advisory.avid: impact for impact in impacts}

        result = []

        for advisory in advisories_qs:
            impact = impact_by_avid.get(advisory.avid)
            if not impact:
                continue

            result.append(
                {
                    "advisory_id": advisory.advisory_id.split("/")[-1],
                    "aliases": [alias.alias for alias in advisory.aliases.all()],
                    "summary": advisory.summary,
                    "fixed_by_packages": [pkg.purl for pkg in impact.fixed_by_packages.all()],
                }
            )

        return result

    def get_fixing_vulnerabilities(self, package):
        advisories_qs = AdvisoryV2.objects.latest_fixed_by_advisories_for_purl(package.package_url)

        advisories = []

        is_grouped = AdvisorySet.objects.filter(package=package, relation_type="fixing").exists()

        if is_grouped:
            fixing_advisories_qs = AdvisorySet.objects.filter(
                package=package, relation_type="fixing"
            ).select_related("primary_advisory")

            fixing_groups = [
                (list(adv.aliases.all()), adv.primary_advisory, "") for adv in fixing_advisories_qs
            ]

            advisories = get_advisories_from_groups(fixing_groups)
            return self.return_fixing_advisories_data(advisories)

        if package.type in TYPES_WITH_MULTIPLE_IMPORTERS:
            advisories_qs = advisories_qs.prefetch_related(
                "aliases",
                "impacted_packages__affecting_packages",
                "impacted_packages__fixed_by_packages",
            )
            advisories = merge_and_save_grouped_advisories(package, advisories_qs, "fixing")
            return self.return_fixing_advisories_data(advisories)

        advisories_ids = advisories_qs.only("id")

        advisories_ids = list(advisories_ids[:101])
        if len(advisories_ids) > 100:
            return None

        results = []

        for advisory in advisories_qs:
            results.append(
                {
                    "advisory_id": advisory.advisory_id.split("/")[-1],
                }
            )
        return results

    def return_fixing_advisories_data(self, advisories):
        result = []
        for advisory in advisories:
            result.append(
                {
                    "advisory_id": advisory["identifier"],
                }
            )

        return result

    def return_advisories_data(self, package, advisories_qs, advisories):
        advisory_by_avid = {adv.avid: adv for adv in advisories_qs}
        avids = advisory_by_avid.keys()

        impacts = (
            package.affected_in_impacts.filter(advisory__avid__in=avids)
            .select_related("advisory")
            .prefetch_related("fixed_by_packages")
        )

        impact_by_avid = {impact.advisory.avid: impact for impact in impacts}

        result = []
        for advisory in advisories:
            impact = impact_by_avid.get(advisory["advisory"].avid)
            if not impact:
                continue

            result.append(
                {
                    "advisory_id": advisory["identifier"],
                    "aliases": [alias.alias for alias in advisory["aliases"]],
                    "summary": advisory["advisory"].summary,
                    "fixed_by_packages": [pkg.purl for pkg in impact.fixed_by_packages.all()],
                }
            )

        return result

    def get_next_non_vulnerable_version(self, package):
        if next_non_vulnerable := package.get_non_vulnerable_versions()[0]:
            return next_non_vulnerable.version

    def get_latest_non_vulnerable_version(self, package):
        if latest_non_vulnerable := package.get_non_vulnerable_versions()[-1]:
            return latest_non_vulnerable.version


class PackageV3ViewSet(viewsets.GenericViewSet):
    queryset = PackageV2.objects.all()
    serializer_class = PackageV3Serializer
    filter_backends = [filters.DjangoFilterBackend]
    throttle_classes = [AnonRateThrottle, PermissionBasedUserRateThrottle]

    def create(self, request, *args, **kwargs):
        serializer = PackageQuerySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        purls = serializer.validated_data["purls"]
        details = serializer.validated_data["details"]
        approximate = serializer.validated_data["approximate"]

        if not purls:
            impacted = ImpactedPackageAffecting.objects.filter(package_id=OuterRef("id"))

            query = (
                PackageV2.objects.annotate(has_vuln=Exists(impacted))
                .filter(has_vuln=True)
                .values_list("package_url", flat=True)
                .order_by("package_url")
            )
            page = self.paginate_queryset(query)
            return self.get_paginated_response(page)

        plain_purls = None

        if approximate:
            plain_purls = [
                str(
                    PackageURL(
                        type=p.type,
                        namespace=p.namespace,
                        name=p.name,
                        version=p.version,
                    )
                )
                for p in map(PackageURL.from_string, purls)
            ]

        if not details:
            if approximate:
                query = (
                    PackageV2.objects.filter(plain_package_url__in=plain_purls)
                    .values_list("plain_package_url", flat=True)
                    .distinct()
                    .order_by("plain_package_url")
                )
            else:
                query = (
                    PackageV2.objects.filter(package_url__in=purls)
                    .distinct()
                    .order_by("package_url")
                    .values_list("package_url", flat=True)
                )

            page = self.paginate_queryset(query)
            return self.get_paginated_response(page)

        if approximate:
            query = (
                PackageV2.objects.filter(plain_package_url__in=plain_purls)
                .order_by("plain_package_url")
                .distinct("plain_package_url")
            )
        else:
            query = (
                PackageV2.objects.filter(package_url__in=purls)
                .order_by("package_url")
                .distinct("package_url")
            )

        page = self.paginate_queryset(query)
        serializer = self.get_serializer(page, many=True, context={"request": request})
        return self.get_paginated_response(serializer.data)


class AffectedByAdvisoryV3Serializer(AdvisoryV3Serializer):
    fixed_by_packages = serializers.SerializerMethodField()

    def get_fixed_by_packages(self, obj):
        return list(
            obj.impacted_packages.values_list("fixed_by_packages__package_url", flat=True)
            .exclude(fixed_by_packages__package_url__isnull=True)
            .distinct()
        )

    class Meta:
        model = AdvisoryV2
        fields = [
            "advisory_id",
            "url",
            "aliases",
            "summary",
            "severities",
            "weaknesses",
            "references",
            "exploitability",
            "weighted_severity",
            "risk_score",
            "related_ssvc_trees",
            "fixed_by_packages",
        ]


class AdvisoryV3ViewSet(viewsets.GenericViewSet):
    queryset = AdvisoryV2.objects.all()
    serializer_class = AdvisoryV3Serializer
    filter_backends = [filters.DjangoFilterBackend]
    throttle_classes = [AnonRateThrottle, PermissionBasedUserRateThrottle]

    def create(self, request, *args, **kwargs):
        serializer = PackageQuerySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        purls = serializer.validated_data["purls"]

        latest_advisories = AdvisoryV2.objects.latest_advisories_for_purls(
            purls=purls
        ).prefetch_related(
            Prefetch(
                "references",
                queryset=AdvisoryReference.objects.only(
                    "id",
                    "url",
                    "reference_type",
                    "reference_id",
                ),
            ),
            Prefetch(
                "severities",
                queryset=AdvisorySeverity.objects.only(
                    "id",
                    "url",
                    "value",
                    "scoring_system",
                    "scoring_elements",
                    "published_at",
                ),
            ),
            "weaknesses",
            "aliases",
            "related_ssvcs__source_advisory",
            "source_ssvcs__source_advisory",
        )

        page = self.paginate_queryset(latest_advisories)
        serializer = self.get_serializer(page, many=True, context={"request": request})
        return self.get_paginated_response(serializer.data)


class PackageAdvisoriesViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = AdvisoryV3Serializer
    relation = None
    throttle_classes = [AnonRateThrottle, PermissionBasedUserRateThrottle]

    def get_queryset(self):
        purl = self.request.query_params.get("purl")

        if not purl:
            return AdvisoryV2.objects.none()

        return AdvisoryV2.objects.filter(**{self.relation: purl}).latest_per_avid()


class FixingAdvisoriesViewSet(PackageAdvisoriesViewSet):
    relation = "impacted_packages__fixed_by_packages__package_url"


class AffectedByAdvisoriesViewSet(PackageAdvisoriesViewSet):
    relation = "impacted_packages__affecting_packages__package_url"
    serializer_class = AffectedByAdvisoryV3Serializer
