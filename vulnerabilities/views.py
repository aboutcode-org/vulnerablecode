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
from packaging import version

from vulnerabilities import forms
from vulnerabilities import models
from vulnerabilities.forms import CVEForm
from vulnerabilities.forms import PackageForm
from vulnerablecode import settings


class PackageSearchView(View):
    template_name = "packages.html"
    ordering = ["version"]

    def get(self, request):
        result_size = 0
        context = {"debug_ui": settings.DEBUG_UI}

        if request.GET:
            packages = self.request_to_queryset(request)
            result_size = len(packages)
            try:
                page_no = request.GET.get("page", 1)
                pages = Paginator(packages, 50)
                packages = Paginator(packages, 50).get_page(page_no)
            except PageNotAnInteger:
                packages = Paginator(packages, 50).get_page(1)
            packages = pages.get_page(page_no)

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
                    "debug_ui": settings.DEBUG_UI,
                }

                if request.GET.get("template") == "packages":
                    context["package_form"] = PackageForm(request.GET or None)
                    context["template_name"] = "packages.html"
                    return render(request, "packages.html", context)
                elif request.GET.get("template") == "package_details":
                    context["package_form"] = PackageForm(request.GET or None)
                    context["template_name"] = "package_update.html"
                    return render(request, "package_update.html", context)
                elif request.GET.get("template") == "index":
                    context["package_form"] = PackageForm(request.GET or None)
                    context["vuln_form"] = CVEForm(request.GET or None)
                    context["template_name"] = "index.html"
                    return render(request, "index.html", context)
                else:
                    context["package_form"] = PackageForm(request.GET or None)
                    context["vuln_form"] = CVEForm(request.GET or None)
                    context["template_name"] = "index.html"
                    return render(request, "index.html", context)

        context["package_form"] = PackageForm(request.GET or None)
        context["template_name"] = self.template_name
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
            pass

        return list(
            models.Package.objects.all()
            .filter(name__icontains=package_name, type__icontains=package_type)
            .order_by("type", "namespace", "name", "version", "subpath", "qualifiers")
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
        context = {"debug_ui": settings.DEBUG_UI}
        result_size = 0

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
                    + request.GET.get("vuln_id")
                    or "" + ".",
                    "debug_ui": settings.DEBUG_UI,
                }

                if request.GET.get("template") == "vulnerabilities":
                    context["vuln_form"] = CVEForm(request.GET or None)
                    context["template_name"] = "vulnerabilities.html"
                    return render(request, "vulnerabilities.html", context)
                elif request.GET.get("template") == "vulnerability_details":
                    context["vuln_form"] = CVEForm(request.GET or None)
                    context["template_name"] = "vulnerability.html"
                    return render(request, "vulnerability.html", context)
                elif request.GET.get("template") == "index":
                    context["package_form"] = PackageForm(request.GET or None)
                    context["vuln_form"] = CVEForm(request.GET or None)
                    context["template_name"] = "index.html"
                    return render(request, "index.html", context)
                else:
                    context["package_form"] = PackageForm(request.GET or None)
                    context["vuln_form"] = CVEForm(request.GET or None)
                    context["template_name"] = "index.html"
                    return render(request, "index.html", context)

        context["vuln_form"] = CVEForm(request.GET or None)
        context["template_name"] = self.template_name
        return render(request, self.template_name, context)

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


class PackageUpdate(UpdateView):
    template_name = "package_update.html"
    model = models.Package
    fields = ["name", "type", "version", "namespace"]

    def get_context_data(self, **kwargs):
        context = super(PackageUpdate, self).get_context_data(**kwargs)
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

        resolved_vuln = [i for i in package.resolved_to]
        unresolved_vuln = [i for i in package.vulnerable_to]

        resolved_vuln = sorted(resolved_vuln, key=lambda x: x.vulnerability_id)
        unresolved_vuln = sorted(unresolved_vuln, key=lambda x: x.vulnerability_id)

        return resolved_vuln, unresolved_vuln

    def _related_packages(self):
        purl = self.get_object()
        return list(
            models.Package.objects.all()
            # We want to ID potential replacement packages -- do we need to also match subpath and qualifiers fields?
            # .filter(Q(type=purl.type, namespace=purl.namespace, name=purl.name))
            .filter(
                Q(
                    type=purl.type,
                    namespace=purl.namespace,
                    name=purl.name,
                    subpath=purl.subpath,
                    qualifiers=purl.qualifiers,
                )
            )
            .order_by("version")
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
        context["aliases"] = vulnerability.aliases.alias()
        # TODO: can we get sort the related packages by version here?

        vulnerability_list = vulnerability.references.all()
        vulnerability_list_count = len(vulnerability_list)
        context["vulnerability_list_count"] = vulnerability_list_count

        context["vuln_form"] = CVEForm(self.request.GET or None)
        context["template_name"] = self.template_name

        severity_list = []
        for ref in self.object_list.all():
            for obj in ref.severities:
                severity_list.append(obj)
        context["severity_list"] = severity_list

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
            "template_name": self.template_name,
            "debug_ui": settings.DEBUG_UI,
        }
        return render(request, self.template_name, context)


def schema_view(request):
    if request.method != "GET":
        return HttpResponseNotAllowed()
    return render(request, "api_doc.html")
