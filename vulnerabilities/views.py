#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging
from collections import defaultdict
from typing import List

from cvss.exceptions import CVSS2MalformedError
from cvss.exceptions import CVSS3MalformedError
from cvss.exceptions import CVSS4MalformedError
from django.contrib import messages
from django.contrib.auth.views import LoginView
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.db.models import Exists
from django.db.models import OuterRef
from django.db.models import Prefetch
from django.http.response import Http404
from django.shortcuts import get_object_or_404
from django.shortcuts import redirect
from django.shortcuts import render
from django.urls import reverse_lazy
from django.views import View
from django.views import generic
from django.views.generic.detail import DetailView
from django.views.generic.edit import FormMixin
from django.views.generic.list import ListView

from vulnerabilities import models
from vulnerabilities.forms import AdminLoginForm
from vulnerabilities.forms import AdvisorySearchForm
from vulnerabilities.forms import ApiUserCreationForm
from vulnerabilities.forms import PackageSearchForm
from vulnerabilities.forms import PipelineSchedulePackageForm
from vulnerabilities.forms import VulnerabilitySearchForm
from vulnerabilities.models import AdvisorySetMember
from vulnerabilities.models import AdvisoryV2
from vulnerabilities.models import Group
from vulnerabilities.models import GroupedAdvisory
from vulnerabilities.models import PipelineRun
from vulnerabilities.models import PipelineSchedule
from vulnerabilities.pipelines.v2_importers.epss_importer_v2 import EPSSImporterPipeline
from vulnerabilities.severity_systems import EPSS
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerabilities.utils import TYPES_WITH_MULTIPLE_IMPORTERS
from vulnerabilities.utils import get_advisories_from_groups
from vulnerabilities.utils import merge_and_save_grouped_advisories
from vulnerablecode import __version__ as VULNERABLECODE_VERSION
from vulnerablecode.settings import env

PAGE_SIZE = 10


class PackageSearch(ListView):
    model = models.Package
    template_name = "packages.html"
    ordering = ["type", "namespace", "name", "version"]
    paginate_by = PAGE_SIZE

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        request_query = self.request.GET
        context["package_search_form"] = PackageSearchForm(request_query)
        context["search"] = request_query.get("search")
        return context

    def get_queryset(self, query=None):
        """
        Return a Package queryset for the ``query``.
        Make a best effort approach to find matching packages either based
        on exact purl, partial purl or just name and namespace.
        """
        query = query or self.request.GET.get("search") or ""
        return (
            self.model.objects.search(query)
            .with_vulnerability_counts()
            .prefetch_related()
            .order_by("package_url")
        )


class VulnerabilitySearch(ListView):
    model = models.Vulnerability
    template_name = "vulnerabilities.html"
    ordering = ["vulnerability_id"]
    paginate_by = PAGE_SIZE

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        request_query = self.request.GET
        context["vulnerability_search_form"] = VulnerabilitySearchForm(request_query)
        context["search"] = request_query.get("search")
        return context

    def get_queryset(self, query=None):
        query = query or self.request.GET.get("search") or ""
        return self.model.objects.search(query=query).with_package_counts()


class PackageDetails(DetailView):
    model = models.Package
    template_name = "package_details.html"
    slug_url_kwarg = "purl"
    slug_field = "purl"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        package = self.object
        context["package"] = package
        context["affected_by_vulnerabilities"] = package.affected_by.order_by("vulnerability_id")
        # Ghost package should not fix any vulnerability.
        context["fixing_vulnerabilities"] = (
            None if package.is_ghost else package.fixing.order_by("vulnerability_id")
        )
        context["package_search_form"] = PackageSearchForm(self.request.GET)
        context["fixed_package_details"] = package.fixed_package_details

        context["history"] = list(package.history)
        return context

    def get_object(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()

        purl = self.kwargs.get(self.slug_url_kwarg)
        if purl:
            queryset = queryset.for_purl(purl)
        else:
            cls = self.__class__.__name__
            raise AttributeError(
                f"Package details view {cls} must be called with a purl, " f"but got: {purl!r}"
            )

        try:
            package = queryset.get()
        except queryset.model.DoesNotExist:
            raise Http404(f"No Package found for purl: {purl}")
        return package


class PackageSearchV2(ListView):
    model = models.PackageV2
    template_name = "packages_v2.html"
    ordering = ["type", "namespace", "name", "version"]
    paginate_by = PAGE_SIZE

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        request_query = self.request.GET
        context["package_search_form"] = PackageSearchForm(request_query)
        context["search"] = request_query.get("search")
        return context

    def get_queryset(self, query=None):
        """
        Return a Package queryset for the ``query``.
        Make a best effort approach to find matching packages either based
        on exact purl, partial purl or just name and namespace.
        """
        query = query or self.request.GET.get("search") or ""
        return self.model.objects.search(query).prefetch_related().with_is_vulnerable()


class AffectedByAdvisoriesListView(ListView):
    model = models.AdvisoryV2
    template_name = "affected_by_advisories.html"
    paginate_by = PAGE_SIZE

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        purl = self.kwargs.get("purl")
        package = models.PackageV2.objects.for_purl(purl).first()
        context["fixed_package_details"] = get_fixed_package_details(package)
        return context

    def get_queryset(self):
        purl = self.kwargs.get("purl")
        return (
            models.AdvisoryV2.objects.latest_affecting_advisories_for_purl(purl)
            .only("advisory_id", "summary", "url", "date_published")
            .prefetch_related("aliases")
        )


class FixingAdvisoriesListView(ListView):
    model = models.AdvisoryV2
    template_name = "fixing_advisories.html"
    paginate_by = PAGE_SIZE

    def get_queryset(self):
        purl = self.kwargs.get("purl")
        return (
            models.AdvisoryV2.objects.latest_fixed_by_advisories_for_purl(purl)
            .only("advisory_id", "summary", "url", "date_published")
            .prefetch_related("aliases")
        )


class PackageV2Details(DetailView):
    model = models.PackageV2
    template_name = "package_details_v2.html"
    slug_url_kwarg = "purl"
    slug_field = "purl"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        package = self.object

        next_non_vulnerable, latest_non_vulnerable = package.get_non_vulnerable_versions()

        context["package"] = package
        context["next_non_vulnerable"] = next_non_vulnerable
        context["latest_non_vulnerable"] = latest_non_vulnerable
        context["package_search_form"] = PackageSearchForm(self.request.GET)

        if not package.type in TYPES_WITH_MULTIPLE_IMPORTERS:
            affecting_advisories = AdvisoryV2.objects.latest_affecting_advisories_for_purl(
                purl=package.purl
            )

            fixed_by_advisories = AdvisoryV2.objects.latest_fixed_by_advisories_for_purl(
                purl=package.purl
            )

            context["grouped"] = False

            affected_by_advisories_url = None
            fixing_advisories_url = None

            affected_by_advisories_qs_ids = affecting_advisories.only("id")
            fixing_advisories_qs_ids = fixed_by_advisories.only("id")

            affected_by_advisories = list(affected_by_advisories_qs_ids[:101])
            if len(affected_by_advisories) > 100:
                affected_by_advisories_url = reverse_lazy(
                    "affected_by_advisories_v2", kwargs={"purl": package.package_url}
                )
                context["affected_by_advisories_v2_url"] = affected_by_advisories_url

            else:
                fixed_pkg_details = get_fixed_package_details(package)
                context["fixed_package_details"] = fixed_pkg_details
                context["affected_by_advisories_v2"] = affecting_advisories
                context["affected_by_advisories_v2_url"] = None

            fixing_advisories = list(fixing_advisories_qs_ids[:101])
            if len(fixing_advisories) > 100:
                fixing_advisories_url = reverse_lazy(
                    "fixing_advisories_v2", kwargs={"purl": package.package_url}
                )
                context["fixing_advisories_v2_url"] = fixing_advisories_url
                context["fixing_advisories_v2"] = []

            else:
                context["fixing_advisories_v2"] = fixed_by_advisories

            return context

        is_grouped = models.AdvisorySet.objects.filter(package=package).exists()

        if is_grouped:
            context["grouped"] = True
            fixed_pkg_details = get_fixed_package_details(package)
            context["fixed_package_details"] = fixed_pkg_details

            affected_by_advisories_qs = (
                models.AdvisorySet.objects.filter(package=package, relation_type="affecting")
                .select_related("primary_advisory")
                .prefetch_related(
                    Prefetch(
                        "members",
                        queryset=AdvisorySetMember.objects.filter(is_primary=False).select_related(
                            "advisory"
                        ),
                        to_attr="secondary_members",
                    )
                )
            )

            fixing_advisories_qs = (
                models.AdvisorySet.objects.filter(package=package, relation_type="fixing")
                .select_related("primary_advisory")
                .prefetch_related(
                    Prefetch(
                        "members",
                        queryset=AdvisorySetMember.objects.filter(is_primary=False).select_related(
                            "advisory"
                        ),
                        to_attr="secondary_members",
                    )
                )
            )

            affected_groups = [
                (
                    Group(
                        aliases=list(adv.aliases.all()),
                        primary=adv.primary_advisory,
                        secondaries=[a.advisory for a in adv.secondary_members],
                    )
                )
                for adv in affected_by_advisories_qs
            ]
            fixing_groups = [
                (
                    Group(
                        aliases=list(adv.aliases.all()),
                        primary=adv.primary_advisory,
                        secondaries=[a.advisory for a in adv.secondary_members],
                    )
                )
                for adv in fixing_advisories_qs
            ]

            affected_advisories: List[GroupedAdvisory] = get_advisories_from_groups(affected_groups)
            fixing_advisories: List[GroupedAdvisory] = get_advisories_from_groups(fixing_groups)

            context["affected_by_advisories_v2"] = affected_advisories
            context["fixing_advisories_v2"] = fixing_advisories

            return context

        if package.type in TYPES_WITH_MULTIPLE_IMPORTERS:
            affecting_advisories = AdvisoryV2.objects.latest_affecting_advisories_for_purl(
                purl=package.purl
            )

            fixed_by_advisories = AdvisoryV2.objects.latest_fixed_by_advisories_for_purl(
                purl=package.purl
            )
            fixed_pkg_details = get_fixed_package_details(package)
            context["fixed_package_details"] = fixed_pkg_details
            context["grouped"] = True

            affecting_advisories = affecting_advisories.prefetch_related(
                "aliases",
                "impacted_packages__affecting_packages",
                "impacted_packages__fixed_by_packages",
            )

            affected_by_advisories: List[GroupedAdvisory] = merge_and_save_grouped_advisories(
                package, affecting_advisories, "affecting"
            )

            fixed_by_advisories = fixed_by_advisories.prefetch_related(
                "aliases",
                "impacted_packages__affecting_packages",
                "impacted_packages__fixed_by_packages",
            )

            fixing_advisories: List[GroupedAdvisory] = merge_and_save_grouped_advisories(
                package, fixed_by_advisories, "fixing"
            )

            context["affected_by_advisories_v2"] = affected_by_advisories
            context["fixing_advisories_v2"] = fixing_advisories
            return context

    def get_object(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()

        purl = self.kwargs.get(self.slug_url_kwarg)
        if purl:
            queryset = queryset.for_purl(purl)
        else:
            cls = self.__class__.__name__
            raise AttributeError(
                f"Package details view {cls} must be called with a purl, " f"but got: {purl!r}"
            )

        try:
            package = queryset.get()
        except queryset.model.DoesNotExist:
            raise Http404(f"No Package found for purl: {purl}")
        return package


class PackageV3Details(DetailView):
    model = models.PackageV2
    template_name = "package_details_v3.html"
    slug_url_kwarg = "purl"
    slug_field = "purl"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        package = self.object

        next_non_vulnerable, latest_non_vulnerable = package.get_non_vulnerable_versions()

        context["package"] = package
        context["next_non_vulnerable"] = next_non_vulnerable
        context["latest_non_vulnerable"] = latest_non_vulnerable
        context["package_search_form"] = PackageSearchForm(self.request.GET)

        affected_by_advisories_qs = (
            models.AdvisorySet.objects.filter(package=package, relation_type="affecting")
            .select_related("primary_advisory")
            .prefetch_related(
                Prefetch(
                    "members",
                    queryset=AdvisorySetMember.objects.filter(is_primary=False).select_related(
                        "advisory"
                    ),
                    to_attr="secondary_members",
                )
            )
        )

        fixing_advisories_qs = (
            models.AdvisorySet.objects.filter(package=package, relation_type="fixing")
            .select_related("primary_advisory")
            .prefetch_related(
                Prefetch(
                    "members",
                    queryset=AdvisorySetMember.objects.filter(is_primary=False).select_related(
                        "advisory"
                    ),
                    to_attr="secondary_members",
                )
            )
        )

        print(affected_by_advisories_qs)
        print(fixing_advisories_qs)

        affected_by_advisories_url = None
        fixing_advisories_url = None

        affected_by_advisories_qs_ids = affected_by_advisories_qs.only("id")
        fixing_advisories_qs_ids = fixing_advisories_qs.only("id")

        # affected_by_advisories = list(affected_by_advisories_qs_ids[:101])
        # if len(affected_by_advisories) > 100:
        #     affected_by_advisories_url = reverse_lazy(
        #         "affected_by_advisories_v2", kwargs={"purl": package.package_url}
        #     )
        #     context["affected_by_advisories_v2_url"] = affected_by_advisories_url
        #     context["affected_by_advisories_v2"] = []
        #     context["fixed_package_details"] = {}

        # else:
        fixed_pkg_details = get_fixed_package_details(package)

        context["affected_by_advisories_v2"] = affected_by_advisories_qs
        context["fixed_package_details"] = fixed_pkg_details
        context["affected_by_advisories_v2_url"] = None

        # fixing_advisories = list(fixing_advisories_qs_ids[:101])
        # if len(fixing_advisories) > 100:
        #     fixing_advisories_url = reverse_lazy(
        #         "fixing_advisories_v2", kwargs={"purl": package.package_url}
        #     )
        #     context["fixing_advisories_v2_url"] = fixing_advisories_url
        #     context["fixing_advisories_v2"] = []

        # else:
        context["fixing_advisories_v2"] = fixing_advisories_qs
        context["fixing_advisories_v2_url"] = None

        return context

    def get_object(self, queryset=None):
        if queryset is None:
            queryset = self.get_queryset()

        purl = self.kwargs.get(self.slug_url_kwarg)
        if purl:
            queryset = queryset.for_purl(purl)
        else:
            cls = self.__class__.__name__
            raise AttributeError(
                f"Package details view {cls} must be called with a purl, " f"but got: {purl!r}"
            )

        try:
            package = queryset.get()
        except queryset.model.DoesNotExist:
            raise Http404(f"No Package found for purl: {purl}")
        return package


def get_fixed_package_details(package):
    rows = package.affected_in_impacts.values_list(
        "advisory__avid",
        "fixed_by_packages",
    )

    pkg_ids = {pkg_id for _, pkg_id in rows if pkg_id}

    pkg_map = {
        p.id: p
        for p in models.PackageV2.objects.filter(id__in=pkg_ids, is_ghost=False).annotate(
            is_vulnerable=Exists(
                models.ImpactedPackage.objects.filter(affecting_packages=OuterRef("pk"))
            )
        )
    }

    fixed_pkg_details = defaultdict(list)

    for avid, pkg_id in rows:
        if not pkg_id:
            continue

        pkg = pkg_map.get(pkg_id)
        if not pkg:
            continue

        fixed_pkg_details[avid].append(
            {
                "pkg": pkg,
                "is_vulnerable": pkg.is_vulnerable,
            }
        )

    return fixed_pkg_details


class VulnerabilityDetails(DetailView):
    model = models.Vulnerability
    template_name = "vulnerability_details.html"
    slug_url_kwarg = "vulnerability_id"
    slug_field = "vulnerability_id"

    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .select_related()
            .prefetch_related(
                Prefetch(
                    "references",
                    queryset=models.VulnerabilityReference.objects.only(
                        "reference_id", "reference_type", "url"
                    ),
                ),
                Prefetch(
                    "aliases",
                    queryset=models.Alias.objects.only("alias"),
                ),
                Prefetch(
                    "weaknesses",
                    queryset=models.Weakness.objects.only("cwe_id"),
                ),
                Prefetch(
                    "severities",
                    queryset=models.VulnerabilitySeverity.objects.only(
                        "scoring_system", "value", "url", "scoring_elements", "published_at"
                    ),
                ),
                Prefetch(
                    "exploits",
                    queryset=models.Exploit.objects.only(
                        "data_source", "description", "required_action", "due_date", "notes"
                    ),
                ),
            )
        )

    def get_context_data(self, **kwargs):
        """
        Build context with preloaded QuerySets and minimize redundant queries.
        """
        context = super().get_context_data(**kwargs)
        vulnerability = self.object

        # Pre-fetch and process data in Python instead of the template
        weaknesses_present_in_db = [
            weakness_object
            for weakness_object in vulnerability.weaknesses.all()
            if weakness_object.weakness
        ]

        valid_severities = self.object.severities.exclude(scoring_system=EPSS.identifier).filter(
            scoring_elements__isnull=False, scoring_system__in=SCORING_SYSTEMS.keys()
        )

        severity_vectors = []

        for severity in valid_severities:
            try:
                vector_values_system = SCORING_SYSTEMS[severity.scoring_system]
                if not vector_values_system:
                    logging.error(f"Unknown scoring system: {severity.scoring_system}")
                    continue
                vector_values = vector_values_system.get(severity.scoring_elements)
                if vector_values:
                    severity_vectors.append({"vector": vector_values, "origin": severity.url})
            except (
                CVSS2MalformedError,
                CVSS3MalformedError,
                CVSS4MalformedError,
                NotImplementedError,
            ):
                logging.error(f"CVSSMalformedError for {severity.scoring_elements}")

        epss_severity = vulnerability.severities.filter(scoring_system="epss").first()
        epss_data = None
        if epss_severity:
            epss_data = {
                "percentile": epss_severity.scoring_elements,
                "score": epss_severity.value,
                "published_at": epss_severity.published_at,
            }

        context.update(
            {
                "vulnerability": vulnerability,
                "vulnerability_search_form": VulnerabilitySearchForm(self.request.GET),
                "severities": list(vulnerability.severities.all()),
                "severity_vectors": severity_vectors,
                "references": list(vulnerability.references.all()),
                "aliases": list(vulnerability.aliases.all()),
                "weaknesses": weaknesses_present_in_db,
                "status": vulnerability.get_status_label,
                "history": vulnerability.history,
                "epss_data": epss_data,
            }
        )
        return context


class AdvisoryDetails(DetailView):
    model = models.AdvisoryV2
    template_name = "advisory_detail.html"
    slug_url_kwarg = "avid"
    slug_field = "avid"

    def get_object(self, queryset=None):
        avid = self.kwargs.get(self.slug_url_kwarg)
        obj = models.AdvisoryV2.objects.latest_for_avid(avid)

        if not obj:
            raise Http404("Advisory not found")

        return obj

    def get_queryset(self):
        return (
            super()
            .get_queryset()
            .select_related()
            .prefetch_related(
                Prefetch(
                    "references",
                    queryset=models.AdvisoryReference.objects.only(
                        "reference_id", "reference_type", "url"
                    ),
                ),
                Prefetch(
                    "aliases",
                    queryset=models.AdvisoryAlias.objects.only("alias"),
                ),
                Prefetch(
                    "weaknesses",
                    queryset=models.AdvisoryWeakness.objects.only("cwe_id"),
                ),
                Prefetch(
                    "severities",
                    queryset=models.AdvisorySeverity.objects.only(
                        "scoring_system", "value", "url", "scoring_elements", "published_at"
                    ),
                ),
                Prefetch(
                    "exploits",
                    queryset=models.AdvisoryExploit.objects.only(
                        "data_source", "description", "required_action", "due_date", "notes"
                    ),
                ),
                Prefetch(
                    "related_ssvcs",
                    queryset=models.SSVC.objects.select_related("source_advisory").only(
                        "vector",
                        "options",
                        "decision",
                        "source_advisory__id",
                        "source_advisory__url",
                    ),
                ),
                Prefetch(
                    "source_ssvcs",
                    queryset=models.SSVC.objects.select_related("source_advisory").only(
                        "vector",
                        "options",
                        "decision",
                        "source_advisory__id",
                        "source_advisory__url",
                    ),
                ),
            )
        )

    def get_context_data(self, **kwargs):
        """
        Build context with preloaded QuerySets and minimize redundant queries.
        """
        context = super().get_context_data(**kwargs)
        advisory = self.object

        # Pre-fetch and process data in Python instead of the template
        weaknesses_present_in_db = [
            weakness_object
            for weakness_object in advisory.weaknesses.all()
            if weakness_object.weakness
        ]

        valid_severities = (
            self.object.severities.exclude(scoring_system=EPSS.identifier)
            .filter(scoring_elements__isnull=False, scoring_system__in=SCORING_SYSTEMS.values())
            .exclude(scoring_elements="")
        )

        epss_severity = advisory.severities.filter(scoring_system="epss").first()
        epss_data = None
        epss_advisory = None
        if not epss_severity:
            epss_advisory = (
                advisory.related_advisory_severities.filter(
                    datasource_id=EPSSImporterPipeline.pipeline_id
                )
                .latest_per_avid()
                .first()
            )
            if epss_advisory:
                epss_severity = epss_advisory.severities.filter(scoring_system="epss").first()
        if epss_severity:
            # If the advisory itself does not have EPSS severity, but has a related advisory with EPSS severity, we use the related advisory's EPSS severity and URL as the source of EPSS data.
            epss_data = {
                "percentile": epss_severity.scoring_elements,
                "score": epss_severity.value,
                "published_at": epss_severity.published_at,
                "source": epss_advisory.url if epss_advisory else advisory.url,
                "advisory": epss_advisory if epss_advisory else advisory,
            }

        ssvc_entries = []
        seen = set()

        severity_vectors = []

        for severity in valid_severities:
            try:
                vector_values_system = SCORING_SYSTEMS.get(severity.scoring_system)
                if not vector_values_system:
                    logging.error(f"Unknown scoring system: {severity.scoring_system}")
                    continue
                if vector_values_system.identifier in ["cvssv3.1_qr"]:
                    continue
                vector_values = vector_values_system.get(severity.scoring_elements)
                if vector_values:
                    severity_vectors.append({"vector": vector_values, "origin": severity.url})
            except (
                CVSS2MalformedError,
                CVSS3MalformedError,
                CVSS4MalformedError,
                NotImplementedError,
            ):
                logging.error(f"CVSSMalformedError for {severity.scoring_elements}")

        def add_ssvc(ssvc):
            key = (ssvc.vector, ssvc.source_advisory_id)
            if key in seen:
                return
            seen.add(key)
            ssvc_entries.append(
                {
                    "vector": ssvc.vector,
                    "decision": ssvc.decision,
                    "options": ssvc.options,
                    "advisory_url": ssvc.source_advisory.url,
                    "advisory": ssvc.source_advisory,
                }
            )

        for ssvc in advisory.source_ssvcs.all():
            add_ssvc(ssvc)

        for ssvc in advisory.related_ssvcs.all():
            add_ssvc(ssvc)

        context["ssvcs"] = ssvc_entries
        context.update(
            {
                "advisory": advisory,
                "severities": list(advisory.severities.all()),
                "references": list(advisory.references.all()),
                "aliases": list(advisory.aliases.all()),
                "severity_vectors": severity_vectors,
                "weaknesses": weaknesses_present_in_db,
                "status": advisory.get_status_label,
                "epss_data": epss_data,
            }
        )
        return context


class HomePage(View):
    template_name = "index.html"

    def get(self, request):
        request_query = request.GET
        context = {
            "vulnerability_search_form": VulnerabilitySearchForm(request_query),
            "package_search_form": PackageSearchForm(request_query),
            "release_url": f"https://github.com/aboutcode-org/vulnerablecode/releases/tag/v{VULNERABLECODE_VERSION}",
        }
        return render(request=request, template_name=self.template_name, context=context)


class HomePageV2(View):
    template_name = "index_v2.html"

    def get(self, request):
        request_query = request.GET
        context = {
            "vulnerability_search_form": AdvisorySearchForm(request_query),
            "package_search_form": PackageSearchForm(request_query),
            "release_url": f"https://github.com/aboutcode-org/vulnerablecode/releases/tag/v{VULNERABLECODE_VERSION}",
        }
        return render(request=request, template_name=self.template_name, context=context)


email_template = """
Dear VulnerableCode.io user:

We have received a request to send a VulnerableCode.io API key to this email address.
Here is your API key:

   Token {auth_token}

If you did NOT request this API key, you can either ignore this email or contact us at support@nexb.com and let us know in the forward that you did not request an API key.

The API root is at https://public.vulnerablecode.io/api
To learn more about using the VulnerableCode.io API, please refer to the live API documentation at https://public.vulnerablecode.io/api/docs
To learn about VulnerableCode, refer to the general documentation at https://vulnerablecode.readthedocs.io

--
Sincerely,
The nexB support Team.

VulnerableCode is a free and open database of software package vulnerabilities
and the tools to aggregate and correlate these vulnerabilities.

Chat at https://gitter.im/aboutcode-org/vulnerablecode
Docs at https://vulnerablecode.readthedocs.org/
Source code and issues at https://github.com/nexB/vulnerablecode
"""


class ApiUserCreateView(generic.CreateView):
    model = models.ApiUser
    form_class = ApiUserCreationForm
    template_name = "api_user_creation_form.html"

    def form_valid(self, form):
        try:
            response = super().form_valid(form)
        except ValidationError:
            messages.error(self.request, "Email is invalid or already taken")
            return redirect(self.get_success_url())

        send_mail(
            subject="VulnerableCode.io API key request",
            message=email_template.format(auth_token=self.object.auth_token),
            from_email=env.str("FROM_EMAIL", default=""),
            recipient_list=[self.object.email],
            fail_silently=True,
        )

        messages.success(
            self.request, f"Your API key token has been sent to your email: {self.object.email}."
        )

        return response

    def get_success_url(self):
        return reverse_lazy("api_user_request")


class VulnerabilityPackagesDetails(DetailView):
    """
    View to display all packages affected by or fixing a specific vulnerability.
    URL: /vulnerabilities/{vulnerability_id}/packages
    """

    model = models.Vulnerability
    template_name = "vulnerability_package_details.html"
    slug_url_kwarg = "vulnerability_id"
    slug_field = "vulnerability_id"

    def get_queryset(self):
        """
        Prefetch and optimize related data to minimize database hits.
        """
        return (
            super()
            .get_queryset()
            .prefetch_related(
                Prefetch(
                    "affecting_packages",
                    queryset=models.Package.objects.only("type", "namespace", "name", "version"),
                ),
                Prefetch(
                    "fixed_by_packages",
                    queryset=models.Package.objects.only("type", "namespace", "name", "version"),
                ),
            )
        )

    def get_context_data(self, **kwargs):
        """
        Build context with preloaded QuerySets and minimize redundant queries.
        """
        context = super().get_context_data(**kwargs)
        vulnerability = self.object
        (
            sorted_fixed_by_packages,
            sorted_affected_packages,
            all_affected_fixed_by_matches,
        ) = vulnerability.aggregate_fixed_and_affected_packages()
        context.update(
            {
                "affected_packages": sorted_affected_packages,
                "fixed_by_packages": sorted_fixed_by_packages,
                "all_affected_fixed_by_matches": all_affected_fixed_by_matches,
            }
        )
        return context


class AdvisoryPackagesDetails(DetailView):
    """
    View to display all packages affected by or fixing a specific vulnerability.
    URL: /advisories/{id}/packages
    """

    model = models.AdvisoryV2
    template_name = "advisory_package_details.html"
    slug_url_kwarg = "avid"

    def get_object(self, queryset=None):
        avid = self.kwargs.get(self.slug_url_kwarg)
        if not avid:
            raise Http404("Missing advisory identifier")

        advisory = models.AdvisoryV2.objects.latest_for_avid(avid)

        if not advisory:
            raise Http404(f"No advisory found for avid: {avid}")

        return advisory

    def get_queryset(self):
        """
        Prefetch and optimize related data to minimize database hits.
        """
        return (
            super()
            .get_queryset()
            .prefetch_related(
                Prefetch(
                    "impacted_packages",
                    queryset=models.ImpactedPackage.objects.prefetch_related(
                        Prefetch(
                            "affecting_packages",
                            queryset=models.PackageV2.objects.only(
                                "type", "namespace", "name", "version"
                            ),
                        ),
                        Prefetch(
                            "fixed_by_packages",
                            queryset=models.PackageV2.objects.only(
                                "type", "namespace", "name", "version"
                            ),
                        ),
                    ),
                )
            )
        )


class PipelineScheduleListView(ListView, FormMixin):
    model = PipelineSchedule
    context_object_name = "schedule_list"
    template_name = "pipeline_dashboard.html"
    paginate_by = 20
    form_class = PipelineSchedulePackageForm

    def get_queryset(self):
        form = self.form_class(self.request.GET)
        if form.is_valid():
            return PipelineSchedule.objects.filter(
                pipeline_id__icontains=form.cleaned_data.get("search")
            )
        return PipelineSchedule.objects.all()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["active_pipeline_count"] = PipelineSchedule.objects.filter(is_active=True).count()
        context["disabled_pipeline_count"] = PipelineSchedule.objects.filter(
            is_active=False
        ).count()
        return context


class PipelineRunListView(ListView):
    model = PipelineRun
    context_object_name = "run_list"
    template_name = "pipeline_run_list.html"
    paginate_by = 20
    slug_url_kwarg = "pipeline_id"
    slug_field = "pipeline_id"

    def get_queryset(self):
        pipeline = get_object_or_404(
            PipelineSchedule,
            pipeline_id=self.kwargs["pipeline_id"],
        )
        return pipeline.pipelineruns.defer("log")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        pipeline = get_object_or_404(
            PipelineSchedule,
            pipeline_id=self.kwargs["pipeline_id"],
        )
        context["pipeline_name"] = pipeline.pipeline_class.__name__
        context["pipeline_description"] = pipeline.description
        return context


class PipelineRunDetailView(DetailView):
    model = PipelineRun
    template_name = "pipeline_run_details.html"
    context_object_name = "run"

    def get_object(self):
        pipeline_id = self.kwargs["pipeline_id"]
        run_id = self.kwargs["run_id"]
        return get_object_or_404(
            PipelineRun,
            pipeline__pipeline_id=pipeline_id,
            run_id=run_id,
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        pipeline_id = self.kwargs["pipeline_id"]
        run_id = self.kwargs["run_id"]
        run = get_object_or_404(
            PipelineRun,
            pipeline__pipeline_id=pipeline_id,
            run_id=run_id,
        )
        context["pipeline_name"] = run.pipeline_class.__name__
        return context


class AdminLoginView(LoginView):
    template_name = "admin_login.html"
    authentication_form = AdminLoginForm

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["site_title"] = "VulnerableCode site admin"
        context["site_header"] = "VulnerableCode Administration"
        return context
