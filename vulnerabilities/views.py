#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.http.response import Http404
from django.shortcuts import redirect
from django.shortcuts import render
from django.urls import reverse_lazy
from django.views import View
from django.views import generic
from django.views.generic.detail import DetailView
from django.views.generic.list import ListView

from vulnerabilities import models
from vulnerabilities.forms import ApiUserCreationForm
from vulnerabilities.forms import PackageSearchForm
from vulnerabilities.forms import VulnerabilitySearchForm
from vulnerabilities.models import Weakness
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
        return self.model.objects.search(query).with_vulnerability_counts().prefetch_related()


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
        context["fixing_vulnerabilities"] = package.fixing.order_by("vulnerability_id")
        context["package_search_form"] = PackageSearchForm(self.request.GET)
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
        return super().get_queryset().prefetch_related("references", "aliases", "weaknesses")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        weaknesses = self.object.weaknesses.all()
        weaknesses_present_in_db = [weakness for weakness in weaknesses if weakness.weakness]
        context.update(
            {
                "vulnerability": self.object,
                "vulnerability_search_form": VulnerabilitySearchForm(self.request.GET),
                "severities": list(self.object.severities),
                "references": self.object.references.all(),
                "aliases": self.object.aliases.all(),
                "affected_packages": self.object.affected_packages.all(),
                "fixed_by_packages": self.object.fixed_by_packages.all(),
                "weaknesses": weaknesses_present_in_db,
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
