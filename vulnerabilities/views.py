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


class PackageSearchView(View):
    template_name = "packages.html"
    # This does not handle version sorting correctly
    ordering = ["version"]

    def get(self, request):
        result_size = 0
        context = {}

        if request.GET:
            packages = self.request_to_queryset(request)
            # Need to sort these correctly by version -- using order_by in request_to_queryset() does not sort versions correctly
            # this throws error when version includes, e.g., 'alpha'
            # packages.sort(key=lambda x: [int(u) for u in x.version.split(".")])

            # no errors but doesn't sort 1.19 after 1.2 (and this test does not sort 1st by type, namespace and name ()and maybe qualifiers and subpath, too?), as it should)
            # packages.sort(key=lambda x: [u for u in x.version.split(".")])

            # try using version from packaging
            # This failed for 1 version -- packaging.version.InvalidVersion: Invalid version: '4.0.0.alpha3.1'
            # per https://packaging.pypa.io/en/latest/version.html:
            # InvalidVersion – If the version does not conform to PEP 440 in any way then this exception will be raised.
            # See https://peps.python.org/pep-0440/
            # packages.sort(key=lambda x: version.Version(x.version))

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
            # 8/8/2022 Monday 4:14:40 PM.  indent `if result_size == 0:` block 1 indent to test error -- vuln has such an indent
            # 8/8/2022 Monday 4:17:43 PM.  Together with changes below, this works, error for `http://127.0.0.1:8001/packages/search` in browser disappears, and all 129 tests just passed!
            if result_size == 0:
                context = {
                    "package_search": "The VCIO DB does not contain a record of the package you entered -- "
                    + request.GET["name"]
                    + ".",
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
        # 8/8/2022 Monday 4:15:57 PM.  test removing else and 1 outdent for the block -- vuln has this structure
        # else:

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
            # this does not handle version sorting correctly
            .order_by("type", "name", "version")
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
        context = {}
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

                # This needs to distinguish between searches made from index.html, vulnerabilities.html
                # and vulnerability.html so that we return render the originating template.  See how we did this for packages.

                context = {
                    "vuln_search": "The VCIO DB does not contain a record of the vulnerability you entered -- "
                    + request.GET.get("vuln_id")
                    or "" + ".",
                    # "vuln_form": CVEForm(request.GET or None),
                    # "package_form": PackageForm(request.GET or None),
                    # "template_name": "index.html",
                }
                # return render(request, "index.html", context)

                if request.GET.get("template") == "vulnerabilities":
                    # context["package_form"] = PackageForm(request.GET or None)
                    context["vuln_form"] = CVEForm(request.GET or None)
                    context["template_name"] = "vulnerabilities.html"
                    return render(request, "vulnerabilities.html", context)
                elif request.GET.get("template") == "vulnerability_details":
                    # context["package_form"] = PackageForm(request.GET or None)
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
            # this sorts by VULCOID
            .order_by("vulnerability_id").annotate(
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

        # Get related packages so we can check their vulnerabilities
        related_packages = self._related_packages()
        # Using order_by below in the method/function doesn't properly sort versions, so need to do that here
        # but this can't handle, e.g., `alpha1` as part of a version, throws error -- `ValueError: invalid literal for int() with base 10: 'alpha1'`
        # related_packages.sort(key=lambda x: [int(u) for u in x.version.split(".")])
        context["related_packages"] = related_packages

        # 8/7/2022 Sunday 11:45:54 AM.  Identify related_packages with 0 reported vulnerabilities
        no_reported_vulns_packages = []
        for pkg in related_packages:
            if pkg.vulnerability_count == 0:
                no_reported_vulns_packages.append(pkg)
        # Sort the no_reported_vulns_packages by version
        # This does not handle version sorting correctly, e.g., 1.2.27 is displayed above 1.2.4
        no_reported_vulns_packages = sorted(no_reported_vulns_packages, key=lambda x: x.version)
        # this seems to work -- no, like the other blocks that check package versions, this throws an
        # error when the version includes alpha characters, e.g., `ValueError: invalid literal for int() with base 10: '2+bedrock-1'`
        # no_reported_vulns_packages.sort(key=lambda x: [int(u) for u in x.version.split(".")])
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

        # Sort the vulnerabilities associated with each purl/unique package name etc.
        resolved_vuln = sorted(resolved_vuln, key=lambda x: x.vulnerability_id)
        unresolved_vuln = sorted(unresolved_vuln, key=lambda x: x.vulnerability_id)

        return resolved_vuln, unresolved_vuln

    # get related packages
    def _related_packages(self):
        purl = self.get_object()
        return list(
            models.Package.objects.all()
            # Try to match the type and name values but not the version value -- also want to match namespace!
            .filter(Q(type=purl.type, namespace=purl.namespace, name=purl.name))
            # This does not handle version sorting correctly so need to do that up above (and we do)
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
        vulnerability = models.Vulnerability.objects.get(id=self.kwargs["pk"])
        context["vulnerability"] = vulnerability
        context["aliases"] = vulnerability.aliases.alias()

        vulnerability_list = vulnerability.references.all()
        vulnerability_list_count = len(vulnerability_list)
        context["vulnerability_list_count"] = vulnerability_list_count

        context["vuln_form"] = CVEForm(self.request.GET or None)
        context["template_name"] = self.template_name

        # vulnerability_ref = models.VulnerabilityReference.objects.get(id=self.kwargs["pk"])
        # context["vulnerability_ref"] = vulnerability_ref

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
            "template_name": self.template_name,
        }
        return render(request, self.template_name, context)


def schema_view(request):
    if request.method != "GET":
        return HttpResponseNotAllowed()
    return render(request, "api_doc.html")
