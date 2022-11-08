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
            queryset = queryset.for_package_url(purl_str=purl, encode=False)
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
        return super().get_queryset().prefetch_related("references", "aliases")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(
            {
                "vulnerability": self.object,
                "vulnerability_search_form": VulnerabilitySearchForm(self.request.GET),
                "severities": list(self.object.severities),
                "references": self.object.references.all(),
                "aliases": self.object.aliases.all(),
                "affected_packages": self.object.affected_packages.all(),
                "fixed_by_packages": self.object.fixed_by_packages.all(),
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
            subject="VulnerableCode.io API key token",
            message=f"Here is your VulnerableCode.io API key token: {self.object.auth_token}",
            from_email=env.str("FROM_EMAIL", default=""),
            recipient_list=[self.object.email],
            fail_silently=True,
        )

        messages.success(
            self.request, f"API key token sent to your email address {self.object.email}."
        )

        return response

    def get_success_url(self):
        return reverse_lazy("api_user_request")
