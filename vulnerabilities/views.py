#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from urllib.parse import urlencode

from django.core.paginator import PageNotAnInteger
from django.core.paginator import Paginator
from django.db.models import Count
from django.db.models import Q
from django.http.response import HttpResponseNotAllowed
from django.shortcuts import render
from django.urls import reverse
from django.views import View
from django.views.generic.edit import UpdateView
from django.views.generic.list import ListView

from packageurl import PackageURL

from vulnerabilities import forms
from vulnerabilities.forms import CVEForm
from vulnerabilities.forms import PackageForm
from vulnerabilities import models


class PackageSearchView(View):
    template_name = "packages.html"

    def get(self, request):
        context = {}

        if request.GET:
            packages = self.request_to_queryset(request)
            result_size = len(packages)
            pages = Paginator(packages, 50)
            packages = pages.get_page(int(self.request.GET.get("page", 1)))
            context["packages"] = packages
            context["searched_for"] = urlencode(
                {param: request.GET[param] for param in request.GET if param != "page"}
            )
            context["result_size"] = result_size

            if len(request.GET["type"]):
                package_type = request.GET["type"]
                context["package_type"] = package_type

            if len(request.GET["name"]):
                package_name = request.GET["name"]
                context["package_name"] = package_name

        if result_size == 0:
            context = {
                "package_search": "The VCIO DB does not contain a record of the package you entered -- "
                + request.GET["name"]
                + ".",
                "vuln_form": CVEForm(request.GET or None),
                "package_form": PackageForm(request.GET or None),
            }
            return render(request, "index.html", context)
        else:
            return render(request, self.template_name, context)

    @staticmethod
    def request_to_queryset(request):
        package_type = ""
        package_name = ""
        purl = ""

        if len(request.GET["type"]):
            package_type = request.GET["type"]

        if len(request.GET["name"]):
            package_name = request.GET["name"]

        # Check whether the input value is a syntactically-correct purl
        try:
            purl = PackageURL.from_string(package_name)
            return list(
                models.Package.objects.all()
                # Try to match the type, name and version values
                .filter(Q(type=purl.type, name=purl.name, version=purl.version))
                .annotate(
                    vulnerability_count=Count(
                        "vulnerabilities",
                        filter=Q(packagerelatedvulnerability__fix=False),
                    ),
                    # TODO: consider renaming to fixed in the future
                    patched_vulnerability_count=Count(
                        "vulnerabilities",
                        filter=Q(packagerelatedvulnerability__fix=True),
                    ),
                )
                .prefetch_related()
            )
        except:
            # If the input value is not a syntactically-correct purl it will throw an error
            # and we'll use the alternative `return list()` just below
            pass

        return list(
            models.Package.objects.all()
            .filter(name__icontains=package_name, type__icontains=package_type)
            .annotate(
                vulnerability_count=Count(
                    "vulnerabilities",
                    filter=Q(packagerelatedvulnerability__fix=False),
                ),
                # TODO: consider renaming to fixed in the future
                patched_vulnerability_count=Count(
                    "vulnerabilities",
                    filter=Q(packagerelatedvulnerability__fix=True),
                ),
            )
            .prefetch_related()
        )


class VulnerabilitySearchView(View):
    template_name = "vulnerabilities.html"

    def get(self, request):
        result_size = ""
        context = {}

        if request.GET:
            vulnerabilities = self.request_to_vulnerabilities(request)
            result_size = len(vulnerabilities)
            pages = Paginator(vulnerabilities, 50)
            vulnerabilities = pages.get_page(int(self.request.GET.get("page", 1)))
            vuln_id = request.GET["vuln_id"]
            context["vulnerabilities"] = vulnerabilities
            context["result_size"] = result_size
            context["vuln_id"] = vuln_id

        if result_size == 0:
            context = {
                "vuln_search": "The VCIO DB does not contain a record of the vulnerability you entered -- "
                + request.GET["vuln_id"]
                + ".",
                "vuln_form": CVEForm(request.GET or None),
                "package_form": PackageForm(request.GET or None),
            }
            return render(request, "index.html", context)
        else:
            return render(request, self.template_name, context)

    @staticmethod
    def request_to_vulnerabilities(request):
        vuln_id = request.GET["vuln_id"]
        return list(
            models.Vulnerability.objects.filter(
                Q(vulnerability_id=vuln_id) | Q(aliases__alias__icontains=vuln_id)
            ).annotate(
                vulnerable_package_count=Count(
                    "packages", filter=Q(packagerelatedvulnerability__fix=False)
                ),
                patched_package_count=Count(
                    "packages", filter=Q(packagerelatedvulnerability__fix=True)
                ),
            )
        )


class PackageUpdate(UpdateView):
    template_name = "package_update.html"
    model = models.Package
    fields = ["name", "type", "version", "namespace"]

    def get_context_data(self, **kwargs):
        context = super(PackageUpdate, self).get_context_data(**kwargs)
        resolved_vuln, unresolved_vuln = self._package_vulnerabilities()
        context["resolved_vuln"] = resolved_vuln
        context["impacted_vuln"] = unresolved_vuln

        return context

    def _package_vulnerabilities(self):
        # This can be further optimised by caching get_object result first time it
        # is called
        package = self.get_object()
        resolved_vuln = [i for i in package.resolved_to]
        unresolved_vuln = [i for i in package.vulnerable_to]

        return resolved_vuln, unresolved_vuln

    def get_success_url(self):
        return reverse("package_view", kwargs={"pk": self.kwargs["pk"]})


class VulnerabilityDetails(ListView):
    template_name = "vulnerability.html"
    model = models.VulnerabilityReference

    def get_context_data(self, **kwargs):
        context = super(VulnerabilityDetails, self).get_context_data(**kwargs)
        vulnerability = models.Vulnerability.objects.get(id=self.kwargs["pk"])
        context["vulnerability"] = vulnerability
        context["aliases"] = vulnerability.aliases.alias()

        vulnerability_list = vulnerability.references.all()
        vulnerability_list_count = len(vulnerability_list)
        context["vulnerability_list_count"] = vulnerability_list_count

        vulnerability_ref = models.VulnerabilityReference.objects.get(id=self.kwargs["pk"])

        context["vulnerability_ref"] = vulnerability_ref

        severity_list = []
        for ref in self.object_list.all():
            for obj in ref.severities:
                severity_list.append(obj)

        return context

    def get_queryset(self):
        return models.VulnerabilityReference.objects.filter(
            vulnerabilityrelatedreference__vulnerability__id=self.kwargs["pk"]
        )


class HomePage(View):
    template_name = "index.html"

    def get(self, request):
        context = {
            "vuln_form": CVEForm(request.GET or None),
            "package_form": PackageForm(request.GET or None),
        }
        return render(request, self.template_name, context)


def schema_view(request):
    if request.method != "GET":
        return HttpResponseNotAllowed()
    return render(request, "api_doc.html")
