#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
import logging

from cvss.exceptions import CVSS2MalformedError
from cvss.exceptions import CVSS3MalformedError
from cvss.exceptions import CVSS4MalformedError
from django.contrib import messages
from django.contrib.auth.views import LoginView
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
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
from vulnerabilities.forms import ApiUserCreationForm
from vulnerabilities.forms import PackageSearchForm
from vulnerabilities.forms import PipelineSchedulePackageForm
from vulnerabilities.forms import VulnerabilitySearchForm
from vulnerabilities.models import PipelineRun
from vulnerabilities.models import PipelineSchedule
from vulnerabilities.severity_systems import EPSS
from vulnerabilities.severity_systems import SCORING_SYSTEMS
from vulnerablecode import __version__ as VULNERABLECODE_VERSION
from vulnerablecode.settings import env

PAGE_SIZE = 20


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
                vector_values = SCORING_SYSTEMS[severity.scoring_system].get(
                    severity.scoring_elements
                )
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


class PipelineScheduleListView(ListView, FormMixin):
    model = PipelineSchedule
    context_object_name = "schedule_list"
    template_name = "pipeline_schedule_list.html"
    paginate_by = 20
    form_class = PipelineSchedulePackageForm

    def get_queryset(self):
        form = self.form_class(self.request.GET)
        if form.is_valid():
            return PipelineSchedule.objects.filter(
                pipeline_id__icontains=form.cleaned_data.get("search")
            )
        return PipelineSchedule.objects.all()


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
