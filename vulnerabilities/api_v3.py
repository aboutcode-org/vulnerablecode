#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from collections import defaultdict
from urllib.parse import urlencode

from django.contrib.postgres.aggregates import ArrayAgg
from django.core.cache import cache
from django.db.models import Exists
from django.db.models import F
from django.db.models import Max
from django.db.models import OuterRef
from django.db.models import Prefetch
from django.db.models import Q
from django_filters import rest_framework as filters
from drf_spectacular.utils import extend_schema
from packageurl import PackageURL
from rest_framework import serializers
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.reverse import reverse
from rest_framework.throttling import AnonRateThrottle
from rest_framework.viewsets import ViewSet

from vulnerabilities.models import SSVC
from vulnerabilities.models import AdvisoryAlias
from vulnerabilities.models import AdvisoryReference
from vulnerabilities.models import AdvisorySet
from vulnerabilities.models import AdvisorySetMember
from vulnerabilities.models import AdvisorySeverity
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import AdvisoryWeakness
from vulnerabilities.models import ImpactedPackageAffecting
from vulnerabilities.models import PackageV2
from vulnerabilities.throttling import PermissionBasedUserRateThrottle
from vulnerabilities.utils import TYPES_WITH_MULTIPLE_IMPORTERS


class PackageQuerySerializer(serializers.Serializer):
    purls = serializers.ListField(
        child=serializers.CharField(),
        required=True,
    )
    details = serializers.BooleanField(default=False)
    ignore_qualifiers_subpath = serializers.BooleanField(default=False)
    max_advisories = serializers.IntegerField(default=100, min_value=1, max_value=10000)
    reachability = serializers.BooleanField(default=False)

    def validate(self, data):
        if not data["purls"]:
            if data["details"] or data["ignore_qualifiers_subpath"]:
                raise serializers.ValidationError(
                    "``details`` and ``ignore_qualifiers_subpath`` must be false when purls is empty"
                )
        return data

    def to_internal_value(self, data):
        unknown = set(data.keys()) - set(self.fields.keys())

        if unknown:
            raise serializers.ValidationError({field: ["Unknown field."] for field in unknown})

        return super().to_internal_value(data)


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
    advisory_uid = serializers.CharField(source="avid", read_only=True)
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
            "advisory_uid",
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
        advisories = self.context["advisory_map"].get(package.id, [])
        if advisories == None:
            # when there are more than advisories more than max_advisories for the request
            return None
        return advisories

    def get_fixing_vulnerabilities(self, package):
        advisories = self.context["fixing_advisory_map"].get(package.id, [])
        if advisories == None:
            # when there are more than advisories more than max_advisories for the request
            return None
        return advisories

    def get_next_non_vulnerable_version(self, package):
        if next_non_vulnerable := package.next_non_vulnerable_version:
            return next_non_vulnerable.version

    def get_latest_non_vulnerable_version(self, package):
        if latest_non_vulnerable := package.latest_non_vulnerable_version:
            return latest_non_vulnerable.version


class PackageV3ViewSet(viewsets.GenericViewSet):
    queryset = PackageV2.objects.all()
    serializer_class = PackageV3Serializer
    filter_backends = [filters.DjangoFilterBackend]
    throttle_classes = [AnonRateThrottle, PermissionBasedUserRateThrottle]

    @extend_schema(request=PackageQuerySerializer)
    def create(self, request, *args, **kwargs):
        serializer = PackageQuerySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        purls = serializer.validated_data["purls"]
        details = serializer.validated_data["details"]
        reachability = serializer.validated_data["reachability"]
        ignore_qualifiers_subpath = serializer.validated_data["ignore_qualifiers_subpath"]
        max_advisories = serializer.validated_data["max_advisories"]

        if not purls:
            query = PackageV2.objects.all_vulnerable_purls().order_by("package_url")
            page = self.paginate_queryset(query)
            return self.get_paginated_response(page)

        plain_purls = None

        if ignore_qualifiers_subpath:
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
            affecting_exists = ImpactedPackageAffecting.objects.filter(
                package_id=OuterRef("pk"),
                impacted_package__advisory___all_impacts_unfurled_at__isnull=False,
                impacted_package__advisory__is_latest=True,
            )
            # Return back vulnerable PURLs only
            if ignore_qualifiers_subpath:
                query = (
                    PackageV2.objects.filter_plain_purls(plain_purls)
                    .values_list("plain_package_url", flat=True)
                    .order_by("plain_package_url")
                )
            else:
                query = (
                    PackageV2.objects.filter_purls(purls)
                    .order_by("package_url")
                    .values_list("package_url", flat=True)
                )

            query = query.annotate(
                is_vulnerable=Exists(affecting_exists),
            ).filter(is_vulnerable=True)

            page = self.paginate_queryset(query)
            return self.get_paginated_response(page)

        if ignore_qualifiers_subpath:
            query = PackageV2.objects.filter_plain_purls(plain_purls).order_by("plain_package_url")
        else:
            query = PackageV2.objects.filter_purls(purls).order_by("package_url")

        if request:
            base_url = request.build_absolute_uri("/")[:-1]
        page = self.paginate_queryset(query)
        affected_advisory_map = get_affected_advisories_bulk(
            page, max_advisories, base_url, reachability
        )
        fixing_advisory_map = get_fixing_advisories_bulk(page, max_advisories, base_url)
        serializer = self.get_serializer(
            page,
            many=True,
            context={
                "request": request,
                "advisory_map": affected_advisory_map,
                "fixing_advisory_map": fixing_advisory_map,
                "max_advisories": max_advisories,
            },
        )
        return self.get_paginated_response(serializer.data)


class PackageTypesView(ViewSet):
    def list(self, request):
        types = cache.get("package_types")

        if types is None:
            types = list(
                PackageV2.objects.values_list("type", flat=True).distinct().order_by("type")
            )

            cache.set("package_types", types, 60 * 60)

        return Response(types)


class AffectedByAdvisoryV3Serializer(AdvisoryV3Serializer):
    fixed_by_packages = serializers.SerializerMethodField()
    advisory_uid = serializers.CharField(source="avid", read_only=True)

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
            "advisory_uid",
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

    @extend_schema(request=AdvisoryQuerySerializer)
    def create(self, request, *args, **kwargs):
        serializer = AdvisoryQuerySerializer(data=request.data)
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
            Prefetch(
                "related_ssvcs",
                queryset=SSVC.objects.only(
                    "id",
                    "vector",
                    "decision",
                    "options",
                    "source_advisory__url",
                ),
            ),
            Prefetch(
                "source_ssvcs",
                queryset=SSVC.objects.only(
                    "id",
                    "vector",
                    "decision",
                    "options",
                    "source_advisory__url",
                ),
            ),
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


def get_patches_bulk(package_ids, advisory_ids):
    """Get introduced and fixed patches"""

    base_qs = ImpactedPackageAffecting.objects.filter(
        package_id__in=package_ids,
        impacted_package__advisory_id__in=advisory_ids,
        impacted_package__advisory__is_latest=True,
        impacted_package__advisory___all_impacts_unfurled_at__isnull=False,
    )

    introduced_rows = base_qs.filter(
        impacted_package__introduced_by_package_commit_patches__isnull=False
    ).values(
        "package_id",
        "impacted_package__advisory_id",
        commit_hash=F("impacted_package__introduced_by_package_commit_patches__commit_hash"),
        vcs_url=F("impacted_package__introduced_by_package_commit_patches__vcs_url"),
    )

    fixed_rows = base_qs.filter(
        impacted_package__fixed_by_package_commit_patches__isnull=False
    ).values(
        "package_id",
        "impacted_package__advisory_id",
        commit_hash=F("impacted_package__fixed_by_package_commit_patches__commit_hash"),
        vcs_url=F("impacted_package__fixed_by_package_commit_patches__vcs_url"),
    )

    introduced_patches_map = defaultdict(list)
    fixed_patches_map = defaultdict(list)

    for row in introduced_rows:
        if row["commit_hash"] or row["vcs_url"]:
            key = (row["package_id"], row["impacted_package__advisory_id"])
            introduced_patches_map[key].append(
                {
                    "commit_hash": row["commit_hash"],
                    "vcs_url": row["vcs_url"],
                }
            )

    for row in fixed_rows:
        if row["commit_hash"] or row["vcs_url"]:
            key = (row["package_id"], row["impacted_package__advisory_id"])
            fixed_patches_map[key].append(
                {
                    "commit_hash": row["commit_hash"],
                    "vcs_url": row["vcs_url"],
                }
            )

    return introduced_patches_map, fixed_patches_map


def build_patch_set_map(patches_map, advisory_ids_by_set):
    """
    Returns:
        {
            advisory_set_id: [
                {
                    "commit_hash": "...",
                    "vcs_url": "...",
                }
            ]
        }
    """
    result = {}

    for advisory_set_id, advisory_ids in advisory_ids_by_set.items():
        seen = set()
        collected = []

        for (package_id, advisory_id), patches in patches_map.items():
            if advisory_id not in advisory_ids:
                continue

            for patch in patches:
                key = (
                    patch["commit_hash"],
                    patch["vcs_url"],
                )

                if key in seen:
                    continue

                seen.add(key)
                collected.append(patch)

        result[advisory_set_id] = collected
    return result


def get_affected_advisories_bulk(packages, max_advisories, base_url, reachability=False):
    package_ids = []
    package_ids_with_multiple_importers = []
    packages_without_multiple_importers = []

    for p in packages:
        package_ids.append(p.id)

        if p.type in TYPES_WITH_MULTIPLE_IMPORTERS:
            package_ids_with_multiple_importers.append(p.id)
        else:
            packages_without_multiple_importers.append(p)

    result = {}

    impacts = (
        ImpactedPackageAffecting.objects.filter(
            package_id__in=package_ids,
            impacted_package__advisory__is_latest=True,
            impacted_package__advisory___all_impacts_unfurled_at__isnull=False,
        )
        .values(
            "package_id",
            "impacted_package__advisory_id",
        )
        .annotate(
            fixed_by_packages=ArrayAgg(
                "impacted_package__fixed_by_packages__package_url",
                distinct=True,
                filter=Q(impacted_package__fixed_by_packages__package_url__isnull=False),
            )
        )
    )

    impact_by_package_and_advisory = {
        (
            row["package_id"],
            row["impacted_package__advisory_id"],
        ): row["fixed_by_packages"]
        or []
        for row in impacts
    }

    # Package types with multiple importers

    advisory_sets = list(
        AdvisorySet.objects.filter(
            package_id__in=package_ids_with_multiple_importers,
            relation_type="affecting",
        )
        .select_related("primary_advisory")
        .prefetch_related(
            Prefetch(
                "aliases",
                queryset=AdvisoryAlias.objects.only("alias"),
            ),
        )
        .annotate(
            max_severity=Max(
                "members__advisory__weighted_severity",
            ),
            max_exploitability=Max(
                "members__advisory__exploitability",
            ),
        )
        .only(
            "id",
            "package_id",
            "primary_advisory__avid",
            "primary_advisory__summary",
            "primary_advisory__advisory_id",
        )
    )

    advisory_set_ids = [a.id for a in advisory_sets]

    member_rows = AdvisorySetMember.objects.filter(
        advisory_set_id__in=advisory_set_ids,
    ).values_list(
        "advisory_set_id",
        "advisory_id",
    )

    advisory_ids_by_set = defaultdict(list)
    all_advisory_ids = set()

    for advisory_set_id, advisory_id in member_rows:
        advisory_ids_by_set[advisory_set_id].append(advisory_id)
        all_advisory_ids.add(advisory_id)

    ssvc_rows = (
        SSVC.objects.filter(
            related_advisories__id__in=all_advisory_ids,
            decision__isnull=False,
        )
        .select_related(
            "source_advisory",
        )
        .values_list(
            "related_advisories__id",
            "vector",
            "decision",
            "options",
            "source_advisory__url",
        )
    )

    ssvc_by_advisory = defaultdict(list)

    for advisory_id, vector, decision, options, source_url in ssvc_rows:
        ssvc_by_advisory[advisory_id].append(
            {
                "vector": vector,
                "decision": decision,
                "options": options,
                "source_url": source_url,
            }
        )

    package_map = defaultdict(list)

    for adv in advisory_sets:
        adv._aliases_cache = [a.alias for a in adv.aliases.all()]

        seen = set()
        ssvc_trees = []

        for advisory_id in advisory_ids_by_set.get(adv.id, ()):
            for ssvc in ssvc_by_advisory.get(advisory_id, []):

                key = ssvc["source_url"]

                if key in seen:
                    continue

                seen.add(key)
                ssvc_trees.append(ssvc)

        adv.ssvc_trees = ssvc_trees

        package_map[adv.package_id].append(adv)

    introduced_patches_by_set = {}
    fixed_patches_by_set = {}
    if reachability:
        introduced_patches_map, fixed_patches_map = get_patches_bulk(
            package_ids,
            advisory_ids=all_advisory_ids,
        )

        introduced_patches_by_set = build_patch_set_map(
            introduced_patches_map,
            advisory_ids_by_set,
        )

        fixed_patches_by_set = build_patch_set_map(
            fixed_patches_map,
            advisory_ids_by_set,
        )

    for package in packages:
        groups = package_map.get(package.id, [])
        grouped = []

        for adv in groups:
            primary = adv.primary_advisory
            fixed_by_packages = impact_by_package_and_advisory.get(
                (package.id, primary.id),
                [],
            )

            max_sev = adv.max_severity or 0.0
            max_exp = adv.max_exploitability or 0.0

            weighted_severity = round(max_sev, 1) if max_sev else None
            exploitability = max_exp or None

            risk_score = round(min(max_exp * max_sev, 10.0), 1) if max_exp and max_sev else None

            identifier = primary.advisory_id.split("/")[-1]

            aliases = [a for a in adv._aliases_cache if a != identifier]

            resource_url = None
            advisory_url = primary.get_absolute_url()

            if base_url and advisory_url:
                resource_url = f"{base_url}{advisory_url}"

            grouped.append(
                {
                    "advisory_id": identifier,
                    "advisory_uid": primary.avid,
                    "aliases": aliases,
                    "summary": primary.summary,
                    "weighted_severity": weighted_severity,
                    "exploitability": exploitability,
                    "risk_score": risk_score,
                    "fixed_by_packages": fixed_by_packages,
                    "introduced_in_patches": introduced_patches_by_set.get(
                        adv.id,
                        [],
                    ),
                    "fixed_in_patches": fixed_patches_by_set.get(
                        adv.id,
                        [],
                    ),
                    "ssvc_trees": adv.ssvc_trees,
                    "resource_url": resource_url,
                }
            )

        result[package.id] = grouped

    # Package types without multiple importers

    packages = list(packages_without_multiple_importers)

    if not packages:
        return result

    package_by_purl = {package.package_url: package for package in packages}

    purls = list(package_by_purl.keys())

    advisory_ids_by_purl = defaultdict(list)

    for purl, advisory_id in AdvisoryV2.objects.latest_affecting_advisory_purls_pairs(purls):
        advisory_ids_by_purl[purl].append(advisory_id)

    allowed_package_ids = []
    allowed_advisory_ids = set()

    for package in packages:
        advisory_ids = advisory_ids_by_purl.get(package.package_url, [])

        if len(advisory_ids) > max_advisories:
            result[package.id] = None
            continue

        allowed_package_ids.append(package.id)
        allowed_advisory_ids.update(advisory_ids)

    if not allowed_package_ids:
        return result

    advisories = AdvisoryV2.objects.filter(
        id__in=allowed_advisory_ids,
    ).prefetch_related(
        "aliases",
        Prefetch(
            "related_ssvcs",
            queryset=(
                SSVC.objects.select_related("source_advisory")
                .only(
                    "id",
                    "decision",
                    "options",
                    "vector",
                    "source_advisory__url",
                )
                .distinct("source_advisory__url")
            ),
            to_attr="prefetched_ssvc_trees",
        ),
    )

    advisory_by_id = {advisory.id: advisory for advisory in advisories}

    for package in packages:

        package_result = []

        for advisory_id in advisory_ids_by_purl.get(package.package_url, []):

            advisory = advisory_by_id.get(advisory_id)

            if not advisory:
                continue

            fixed_by_packages = impact_by_package_and_advisory.get(
                (package.id, advisory_id),
                [],
            )

            identifier = advisory.advisory_id.split("/")[-1]

            aliases = [alias.alias for alias in advisory.aliases.all() if alias.alias != identifier]

            resource_url = None
            advisory_url = advisory.get_absolute_url()

            if base_url and advisory_url:
                resource_url = f"{base_url}{advisory_url}"

            package_result.append(
                {
                    "advisory_id": identifier,
                    "advisory_uid": advisory.avid,
                    "aliases": aliases,
                    "summary": advisory.summary,
                    "weighted_severity": advisory.weighted_severity,
                    "exploitability": advisory.exploitability,
                    "risk_score": advisory.risk_score,
                    "fixed_by_packages": fixed_by_packages,
                    "introduced_in_patches": introduced_patches_by_set.get(advisory_id, []),
                    "fixed_in_patches": introduced_patches_by_set.get(advisory_id, []),
                    "ssvc_trees": [
                        {
                            "vector": ssvc.vector,
                            "decision": ssvc.decision,
                            "options": ssvc.options,
                            "source_url": ssvc.source_advisory.url,
                        }
                        for ssvc in advisory.prefetched_ssvc_trees
                    ],
                    "resource_url": resource_url,
                }
            )

        result[package.id] = package_result

    return result


def get_fixing_advisories_bulk(packages, max_advisories, base_url):
    package_ids = []
    package_ids_with_multiple_importers = []
    packages_without_multiple_importers = []

    for p in packages:
        package_ids.append(p.id)

        if p.type in TYPES_WITH_MULTIPLE_IMPORTERS:
            package_ids_with_multiple_importers.append(p.id)
        else:
            packages_without_multiple_importers.append(p)

    advisory_sets = list(
        AdvisorySet.objects.filter(
            package_id__in=package_ids_with_multiple_importers,
            relation_type="fixing",
        )
        .select_related("primary_advisory")
        .only(
            "id",
            "package_id",
            "primary_advisory__advisory_id",
        )
    )

    package_map = defaultdict(list)

    for adv in advisory_sets:
        package_map[adv.package_id].append(adv.primary_advisory)

    result = {}

    for package in packages:
        groups = package_map.get(package.id, [])
        grouped = []

        for advisory in groups:
            resource_url = None
            advisory_url = advisory.get_absolute_url()

            if base_url and advisory_url:
                resource_url = f"{base_url}{advisory_url}"
            grouped.append(
                {
                    "advisory_id": advisory.advisory_id.split("/")[-1],
                    "resource_url": resource_url,
                    "advisory_uid": advisory.avid,
                }
            )

        result[package.id] = grouped

    packages = list(packages_without_multiple_importers)

    if not packages:
        return result

    package_by_purl = {package.package_url: package for package in packages}

    purls = list(package_by_purl.keys())

    advisory_ids_by_purl = defaultdict(list)

    for purl, advisory_id in AdvisoryV2.objects.latest_fixed_by_advisory_purls_pairs(purls):
        advisory_ids_by_purl[purl].append(advisory_id)

    allowed_package_ids = []
    allowed_advisory_ids = set()

    for package in packages:
        advisory_ids = advisory_ids_by_purl.get(package.package_url, [])

        if len(advisory_ids) > max_advisories:
            result[package.id] = None
            continue

        allowed_package_ids.append(package.id)
        allowed_advisory_ids.update(advisory_ids)

    if not allowed_package_ids:
        return result

    advisories = AdvisoryV2.objects.filter(
        id__in=allowed_advisory_ids,
    )

    advisory_by_id = {advisory.id: advisory for advisory in advisories}

    for package in packages:

        package_result = []

        for advisory_id in advisory_ids_by_purl.get(package.package_url, []):

            advisory = advisory_by_id.get(advisory_id)

            if not advisory:
                continue

            resource_url = None
            advisory_url = advisory.get_absolute_url()

            if base_url and advisory_url:
                resource_url = f"{base_url}{advisory_url}"

            package_result.append(
                {
                    "advisory_id": advisory.advisory_id.split("/")[-1],
                    "resource_url": resource_url,
                    "advisory_uid": advisory.avid,
                }
            )
        result[package.id] = package_result

    return result
