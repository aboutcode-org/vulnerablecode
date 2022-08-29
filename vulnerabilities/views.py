#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from urllib.parse import urlencode

from django.conf import settings
from django.core.paginator import Paginator
from django.db.models import Count
from django.db.models import Q
from django.http.response import HttpResponseNotAllowed
from django.shortcuts import render
from django.urls import reverse
from django.views import View
from django.views.generic.list import ListView
from packageurl import PackageURL

from vulnerabilities import models
from vulnerabilities.forms import PackageForm
from vulnerabilities.forms import VulnerabilityForm


class PackageSearchView(View):
    template_name = "packages.html"
    ordering = ["version"]

    def get(self, request):
        result_size = 0
        context = {"debug_ui": settings.DEBUG_UI}

        if request.GET:
            packages = self.request_to_queryset(request)
            result_size = len(packages)

            if not packages:
                return self.render_no_packages(request=request)

            page_no = request.GET.get("page", 1)
            try:
                page_no = int(page_no)
            except ValueError:
                page_no = 1

            packages = Paginator(packages, per_page=PAGE_SIZE).get_page(page_no)
            context["packages"] = packages
            context["searched_for"] = urlencode(
                {param: request.GET[param] for param in request.GET if param != "page"}
            )
            context["result_size"] = result_size

            package_type = request.GET["type"]
            if package_type:
                context["package_type"] = package_type

            package_name = request.GET["name"]
            if package_name:
                context["package_name"] = package_name

        context["package_form"] = PackageForm(request.GET or None)
        context["template_name"] = self.template_name
        return render(request, self.template_name, context)

    def render_no_packages(self, request):
        context = {
            "package_search": "Package not found.",
            "debug_ui": settings.DEBUG_UI,
        }

        template = request.GET.get("template")
        context["package_form"] = PackageForm(request.GET or None)

        if template == "packages":
            context["template_name"] = "packages.html"
            return render(request, "packages.html", context)

        elif template == "package":
            context["template_name"] = "package.html"
            return render(request, "package.html", context)

        else:
            context["vulnerability_form"] = VulnerabilityForm(request.GET or None)
            context["template_name"] = "index.html"
            return render(request, "index.html", context)

    @staticmethod
    def request_to_queryset(request):
        """
        Return a list of Package objects for a ``request`` object.
        """
        package_type = request.GET["type"] or ""
        package_name = request.GET["name"] or ""
        purl = ""

        # Check whether the input value is a syntactically-correct purl
        try:
            purl = PackageURL.from_string(package_name)
            qs = models.Package.objects.filter(
                type=purl.type,
                namespace=purl.namespace,
                name=purl.name,
                version=purl.version,
            )
        except ValueError:
            qs = models.Package.objects.filter(
                type__icontains=package_type,
                name__icontains=package_name,
            )

        return list(
            qs.annotate(
                vulnerability_count=Count(
                    "vulnerabilities",
                    filter=Q(packagerelatedvulnerability__fix=False),
                ),
                patched_vulnerability_count=Count(
                    "vulnerabilities",
                    filter=Q(packagerelatedvulnerability__fix=True),
                ),
            ).prefetch_related()
        )


PAGE_SIZE = 50


class VulnerabilitySearchView(View):
    template_name = "vulnerabilities.html"

    def get(self, request):
        context = {"debug_ui": settings.DEBUG_UI}
        result_size = 0

        if request.GET:
            vulnerabilities = self.request_to_vulnerabilities(request)
            result_size = len(vulnerabilities)
            pages = Paginator(vulnerabilities, per_page=PAGE_SIZE)
            vulnerabilities = pages.get_page(int(self.request.GET.get("page", 1)))
            if not vulnerabilities:
                return self.render_no_vuln(request=request)

            vuln_id = request.GET["vuln_id"]
            context["vulnerabilities"] = vulnerabilities
            context["result_size"] = result_size
            context["vuln_id"] = vuln_id

        context["vulnerability_form"] = VulnerabilityForm(request.GET or None)
        context["template_name"] = self.template_name
        return render(request=request, template_name=self.template_name, context=context)

    def render_no_vuln(self, request):
        context = {
            "vuln_search": f"Vulnerability not found",
            "debug_ui": settings.DEBUG_UI,
        }

        context["vulnerability_form"] = VulnerabilityForm(request.GET or None)
        template = request.GET.get("template")

        if template == "vulnerabilities":
            context["template_name"] = "vulnerabilities.html"
            return render(request=request, template_name="vulnerabilities.html", context=context)

        elif template == "vulnerability_details":
            context["template_name"] = "vulnerability_details.html"
            return render(
                request=request, template_name="vulnerability_details.html", context=context
            )

        else:
            context["package_form"] = PackageForm(request.GET or None)
            context["template_name"] = "index.html"
            return render(request=request, template_name="index.html", context=context)

    @staticmethod
    def request_to_vulnerabilities(request):
        vuln_id = request.GET["vuln_id"]
        return list(
            models.Vulnerability.objects.filter(
                Q(vulnerability_id=vuln_id) | Q(aliases__alias__icontains=vuln_id)
            )
            .order_by("vulnerability_id")
            .annotate(
                vulnerable_package_count=Count(
                    "packages", filter=Q(packagerelatedvulnerability__fix=False), distinct=True
                ),
                patched_package_count=Count(
                    "packages", filter=Q(packagerelatedvulnerability__fix=True), distinct=True
                ),
            )
        )


class PackageDetails(View):
    template_name = "package_details.html"
    model = models.Package
    fields = ["type", "name", "namespace", "version"]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["debug_ui"] = settings.DEBUG_UI
        resolved_vuln, unresolved_vuln = self._package_vulnerabilities()
        context["resolved_vuln"] = resolved_vuln
        context["impacted_vuln"] = unresolved_vuln

        related_packages = self._related_packages()
        context["related_packages"] = related_packages

        no_reported_vulns_packages = []
        for pkg in related_packages:
            if pkg.vulnerability_count == 0:
                no_reported_vulns_packages.append(pkg)

        no_reported_vulns_packages = sorted(no_reported_vulns_packages, key=lambda x: x.version)
        context["no_reported_vulns_packages"] = no_reported_vulns_packages

        context["package_form"] = PackageForm(self.request.GET or None)
        context["template_name"] = self.template_name
        return context

    def _package_vulnerabilities(self):
        # This can be further optimised by caching get_object result first time it
        # is called
        package = self.get_object()

        resolved_vuln = sorted(package.resolved_to, key=lambda x: x.vulnerability_id)
        unresolved_vuln = sorted(package.vulnerable_to, key=lambda x: x.vulnerability_id)

        return resolved_vuln, unresolved_vuln

    def _related_packages(self):
        package = self.get_object()
        return list(
            models.Package.objects.filter(
                type=package.type,
                namespace=package.namespace,
                name=package.name,
                subpath=package.subpath,
                qualifiers=package.qualifiers,
            )
            .order_by("version")
            .annotate(
                vulnerability_count=Count(
                    "vulnerabilities",
                    filter=Q(packagerelatedvulnerability__fix=False),
                ),
                patched_vulnerability_count=Count(
                    "vulnerabilities",
                    filter=Q(packagerelatedvulnerability__fix=True),
                ),
            )
            .prefetch_related()
        )

    def get_success_url(self):
        return reverse("package_view", kwargs={"pk": self.kwargs["pk"]})


class VulnerabilityDetails(ListView):
    template_name = "vulnerability.html"
    model = models.VulnerabilityReference

    def get_context_data(self, **kwargs):
        context = super(VulnerabilityDetails, self).get_context_data(**kwargs)
        context["debug_ui"] = settings.DEBUG_UI

        vulnerability = models.Vulnerability.objects.get(id=self.kwargs["pk"])
        context["vulnerability"] = vulnerability
        context["aliases"] = vulnerability.aliases

        context["vulnerability_form"] = VulnerabilityForm(self.request.GET or None)
        context["template_name"] = self.template_name

        severities = []
        for reference in self.object_list.all():
            for severity in reference.severities:
                severities.append(severity)
        context["severities"] = severities

        return context

    def get_queryset(self):
        return models.VulnerabilityReference.objects.filter(
            vulnerabilityrelatedreference__vulnerability__id=self.kwargs["pk"]
        )


class HomePage(View):
    template_name = "index.html"

    def get(self, request):
        context = {
            "vulnerability_form": VulnerabilityForm(request.GET or None),
            "package_form": PackageForm(request.GET or None),
            "template_name": self.template_name,
            "debug_ui": settings.DEBUG_UI,
        }
        return render(request, self.template_name, context)


def schema_view(request):
    if request.method != "GET":
        return HttpResponseNotAllowed()
    return render(request, "api_doc.html")
