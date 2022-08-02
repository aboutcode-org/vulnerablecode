#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

# This is for the VCIO environment variables
from os import getenv

import requests
import json

from urllib.parse import urlencode

# This 'django.conf' is for the VCIO environment variables
from django.conf import settings
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

# to test 2+ forms in 1 template, try SCIO approach:
from vulnerabilities.forms import CVEForm
from vulnerabilities.forms import PackageForm
from vulnerabilities import models


# This is for the VCIO environment variables
def get_settings(var_name, default=None):
    """
    Return the settings value from the environment or Django settings.
    """
    return getenv(var_name) or getattr(settings, var_name, default)


class PackageSearchView(View):
    template_name = "packages.html"

    def get(self, request):
        context = {"form": forms.PackageForm(request.GET or None)}

        if request.GET:
            packages = self.request_to_queryset(request)
            result_size = len(packages)
            try:
                page_no = request.GET.get("page", 1)
                packages = Paginator(packages, 50).get_page(page_no)
            except PageNotAnInteger:
                packages = Paginator(packages, 50).get_page(1)
            packages = Paginator(packages, 50).get_page(page_no)
            context["packages"] = packages
            context["searched_for"] = urlencode(
                {param: request.GET[param] for param in request.GET if param != "page"}
            )
            context["result_size"] = result_size

        return render(request, self.template_name, context)

    @staticmethod
    def request_to_queryset(request):
        package_type = ""
        package_name = ""

        if len(request.GET["type"]):
            package_type = request.GET["type"]

        if len(request.GET["name"]):
            package_name = request.GET["name"]

        return list(
            models.Package.objects.all()
            # FIXME: This filter is wrong and ignoring most of the fields needed for a
            # proper package lookup: type/namespace/name@version?qualifiers and so on
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


class PackageSearchView_new(View):
    template_name = "packages_new.html"

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

            # Can we add package_type and Package_name to context?
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
                # "vuln_form": CVEForm(),
                # "package_form": PackageForm(),
                "vuln_form": CVEForm(request.GET or None),
                "package_form": PackageForm(request.GET or None),
            }
            return render(request, "index_new.html", context)
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

        # 1st check whether the input value is a syntactically-correct purl
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
        context = {"form": forms.CVEForm(request.GET or None)}
        if request.GET:
            vulnerabilities = self.request_to_vulnerabilities(request)
            result_size = len(vulnerabilities)
            pages = Paginator(vulnerabilities, 50)
            vulnerabilities = pages.get_page(int(self.request.GET.get("page", 1)))
            context["vulnerabilities"] = vulnerabilities
            context["result_size"] = result_size

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


class VulnerabilitySearchView_new(View):
    template_name = "vulnerabilities_new.html"

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
                # "vuln_form": CVEForm(),
                # "package_form": PackageForm(),
                "vuln_form": CVEForm(request.GET or None),
                "package_form": PackageForm(request.GET or None),
            }
            return render(request, "index_new.html", context)
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


class PackageUpdate_new(UpdateView):
    # template_name = "package_update.html"
    template_name = "package_update_new.html"
    model = models.Package
    fields = ["name", "type", "version", "namespace"]

    def get_context_data(self, **kwargs):
        # context = super(PackageUpdate, self).get_context_data(**kwargs)
        context = super(PackageUpdate_new, self).get_context_data(**kwargs)
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
        # return reverse("package_view", kwargs={"pk": self.kwargs["pk"]})
        return reverse("package_view_new", kwargs={"pk": self.kwargs["pk"]})


class VulnerabilityDetails(ListView):
    template_name = "vulnerability.html"
    model = models.VulnerabilityReference

    def get_context_data(self, **kwargs):
        context = super(VulnerabilityDetails, self).get_context_data(**kwargs)
        vulnerability = models.Vulnerability.objects.get(id=self.kwargs["pk"])
        context["vulnerability"] = vulnerability
        context["aliases"] = vulnerability.aliases.alias()
        return context

    def get_queryset(self):
        return models.VulnerabilityReference.objects.filter(
            vulnerabilityrelatedreference__vulnerability__id=self.kwargs["pk"]
        )


class VulnerabilityDetails_new(ListView):
    template_name = "vulnerability_new.html"
    model = models.VulnerabilityReference

    def get_context_data(self, **kwargs):
        context = super(VulnerabilityDetails_new, self).get_context_data(**kwargs)
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
        return render(request, self.template_name)


class HomePage_new(View):
    template_name = "index_new.html"

    def get(self, request):
        context = {
            # "vuln_form": CVEForm(),
            # "package_form": PackageForm(),
            "vuln_form": CVEForm(request.GET or None),
            "package_form": PackageForm(request.GET or None),
        }
        return render(request, self.template_name, context)


def schema_view(request):
    if request.method != "GET":
        return HttpResponseNotAllowed()
    return render(request, "api_doc.html")


# 7/31/2022 Sunday 4:47:09 PM.  Disable this by renaming temporarily because API search is not working, paste older code below to test
class PurlSearchView02(View):
    # class PurlSearchView02_saved(View):
    template_name = "purl02.html"
    all_purls = {}
    all_packages = {}
    all_packages_results = "N/A"
    all_packages_count = "N/A"
    len_all_purls = "N/A"
    all_purls_count = "N/A"
    purl_string = "N/A"
    len_purl_string = len(purl_string)
    your_search = ""
    results_0 = "N/A"
    results_0_purl = "N/A"
    results_0_type = "N/A"
    results_0_namespace = "N/A"
    results_0_name = "N/A"
    results_0_version = "N/A"
    results_0_qualifiers = "N/A"
    results_0_subpath = "N/A"
    affected_by_vulnerabilities = "N/A"
    len_affected_by_vulnerabilities = "N/A"
    fixing_vulnerabilities = "N/A"
    len_fixing_vulnerabilities = "N/A"
    aliases = "N/A"
    all_aliases = {}
    fixing_all_aliases = {}
    affected_html_list = []
    fixing_html_list = []

    VULNERABLECODE_USER = get_settings("VULNERABLECODE_USER")
    VULNERABLECODE_PASSWORD = get_settings("VULNERABLECODE_PASSWORD")
    VULNERABLECODE_URL = get_settings("VULNERABLECODE_URL", default="")
    VULNERABLECODE_API_URL = get_settings("VULNERABLECODE_API_URL")

    session = requests.Session()
    session.auth = (VULNERABLECODE_USER, VULNERABLECODE_PASSWORD)

    vcio_url_vulnerabilities_url = f"{VULNERABLECODE_URL}vulnerabilities/"
    vcio_url_vulnerabilities = session.get(vcio_url_vulnerabilities_url)
    vcio_url_vulnerabilities_string = f"{VULNERABLECODE_URL}vulnerabilities/"

    # Consider renaming this to "vcio_url_packages"
    pkg_html_url = f"{VULNERABLECODE_URL}packages/"

    packageid = "N/A"
    packageid_dict = {}

    def get(self, request):
        if "category" in request.GET and request.GET["category"] == "package":
            if "purl_string" in request.GET and request.GET["purl_string"] != "":
                self.your_search = request.GET["purl_string"]

                all_packages_url = f"{self.VULNERABLECODE_API_URL}packages?name={self.your_search}"
                self.all_packages = self.session.get(all_packages_url).json()

                if self.all_packages["count"] != 0:
                    pass
                else:
                    self.your_search = (
                        "The VCIO DB does not contain a record of the package name you entered -- "
                        + request.GET["purl_string"]
                    )
                    return render(
                        request,
                        "index_new.html",
                        {
                            "your_search": self.your_search,
                            # don't think we need this 1st form key/value pair any longer
                            # "form": forms.CVEForm(request.GET or None),
                            # "vuln_form": CVEForm(),
                            # "package_form": PackageForm(),
                            "vuln_form": CVEForm(request.GET or None),
                            "package_form": PackageForm(request.GET or None),
                        },
                    )

            else:
                self.your_search = (
                    "Please select 'package' from the dropdown and add a value to the search box."
                )
                return render(
                    request,
                    "index_new.html",
                    {
                        "your_search": self.your_search,
                        # don't think we need this 1st form key/value pair any longer
                        # "form": forms.CVEForm(request.GET or None),
                        # "vuln_form": CVEForm(),
                        # "package_form": PackageForm(),
                        "vuln_form": CVEForm(request.GET or None),
                        "package_form": PackageForm(request.GET or None),
                    },
                )
            self.all_packages_results = self.all_packages["results"]

            self.all_packages_count = self.all_packages["count"]
            self.packageid_dict = {}
            for pkg in self.all_packages_results:
                self.packageid = pkg["url"].rsplit("/", 1)[-1]
                self.packageid_dict[pkg["purl"]] = self.packageid

            return render(
                request,
                "packages01.html",
                {
                    "your_search": self.your_search,
                    "all_packages": self.all_packages,
                    "all_packages_results": self.all_packages_results,
                    "all_packages_count": self.all_packages_count,
                    "packageid": self.packageid,
                    "packageid_dict": self.packageid_dict,
                    "pkg_html_url": self.pkg_html_url,
                },
            )

        # if "purl_string" in request.GET:
        #     self.purl_string = request.GET["purl_string"]
        #     if len(self.purl_string) == 0:
        #         self.your_search = "Please add a value in the search box."
        #         return render(
        #             request,
        #             "index_new.html",
        #             {
        #                 "your_search": self.your_search,
        #                 # don't think we need this 1st form key/value pair any longer
        #                 # "form": forms.CVEForm(request.GET or None),
        #                 "vuln_form": CVEForm(),
        #                 "package_form": PackageForm(),
        #             },
        #         )
        #     else:
        #         self.your_search = request.GET["purl_string"]

        #         # Test whether input is a valid purl.
        #         try:
        #             PackageURL.from_string(self.purl_string)
        #         except Exception as e:
        #             self.your_search = (
        #                 "Your input is not a syntactically valid purl -- "
        #                 + str(e)
        #                 + " \r\rIf you're searching by package name rather than purl, please make sure you select 'package' from the dropdown and then add your package name to the search box."
        #             )
        #             return render(
        #                 request,
        #                 "index_new.html",
        #                 {
        #                     "your_search": self.your_search,
        #                     # don't think we need this 1st form key/value pair any longer
        #                     # "form": forms.CVEForm(request.GET or None),
        #                     "vuln_form": CVEForm(),
        #                     "package_form": PackageForm(),
        #                 },
        #             )

        if "purl_string" in request.GET:
            self.purl_string = request.GET["purl_string"]
            # =====================================================uncomment below briefly
            if len(self.purl_string) == 0:
                self.your_search = "Please add a value in the search box."
                return render(
                    request,
                    "index_new.html",
                    {
                        "your_search": self.your_search,
                        # don't think we need this 1st form key/value pair any longer
                        # "form": forms.CVEForm(request.GET or None),
                        "vuln_form": CVEForm(),
                        "package_form": PackageForm(),
                    },
                )
            else:
                # =====================================================uncomment above briefly
                # =====================================================below chunk (down to all_purls_url) needs to be indented
                self.your_search = request.GET["purl_string"]

                # Test whether input is a valid purl.
                try:
                    PackageURL.from_string(self.purl_string)
                except Exception as e:
                    self.your_search = (
                        "Your input is not a syntactically valid purl -- "
                        + str(e)
                        + " \r\rIf you're searching by package name rather than purl, please make sure you select 'package' from the dropdown and then add your package name to the search box."
                    )
                    return render(
                        request,
                        "index_new.html",
                        {
                            "your_search": self.your_search,
                            # don't think we need this 1st form key/value pair any longer
                            # "form": forms.CVEForm(request.GET or None),
                            # "vuln_form": CVEForm(),
                            # "package_form": PackageForm(),
                            "vuln_form": CVEForm(request.GET or None),
                            "package_form": PackageForm(request.GET or None),
                        },
                    )
                # ==================================================above chunk
                # (starting just below else) needed to be indented and all works fine now with these changes -- uncomment 1 chunk and indent the other chunk!

                all_purls_url = f"{self.VULNERABLECODE_API_URL}packages?purl={self.purl_string}"
                self.all_purls = self.session.get(all_purls_url).json()

                if self.all_purls:
                    self.len_all_purls = len(self.all_purls)
                    if "count" in self.all_purls.keys():
                        self.all_purls_count = self.all_purls["count"]
                        if self.all_purls_count == 0:
                            self.your_search = (
                                "The VCIO DB does not contain a record of the purl you entered -- "
                                + request.GET["purl_string"]
                            )
                            return render(
                                request,
                                "index_new.html",
                                {
                                    "your_search": self.your_search,
                                    # don't think we need this 1st form key/value pair any longer
                                    # "form": forms.CVEForm(request.GET or None),
                                    "vuln_form": CVEForm(),
                                    "package_form": PackageForm(),
                                },
                            )
                        elif self.all_purls_count == 1:
                            self.results_0 = self.all_purls["results"][0]
                            self.results_0_purl = self.results_0["purl"]
                            self.results_0_type = self.results_0["type"]
                            self.results_0_namespace = self.results_0["namespace"]
                            self.results_0_name = self.results_0["name"]
                            self.results_0_version = self.results_0["version"]
                            self.results_0_qualifiers = self.results_0["qualifiers"]
                            self.results_0_subpath = self.results_0["subpath"]
                            self.affected_by_vulnerabilities = self.results_0[
                                "affected_by_vulnerabilities"
                            ]
                            self.fixing_vulnerabilities = self.results_0["fixing_vulnerabilities"]
                            self.len_affected_by_vulnerabilities = len(
                                self.affected_by_vulnerabilities
                            )
                            self.len_fixing_vulnerabilities = len(self.fixing_vulnerabilities)

                            self.all_aliases = {}
                            self.affected_html_list = []
                            for vuln in self.affected_by_vulnerabilities:
                                url_split_id = vuln["url"].rsplit("/", 1)[-1]
                                vulcoid = vuln["vulnerability_id"]

                                aliases_url = (
                                    f"{self.VULNERABLECODE_API_URL}vulnerabilities/{url_split_id}"
                                )
                                self.aliases = self.session.get(aliases_url).json()

                                self.all_aliases[vulcoid] = self.aliases["aliases"]

                                self.affected_html_list.append({vulcoid: url_split_id})

                            self.fixing_all_aliases = {}
                            self.fixing_html_list = []
                            for vuln in self.fixing_vulnerabilities:
                                url_split_id = vuln["url"].rsplit("/", 1)[-1]
                                vulcoid = vuln["vulnerability_id"]

                                aliases_url = (
                                    f"{self.VULNERABLECODE_API_URL}vulnerabilities/{url_split_id}"
                                )
                                self.aliases = self.session.get(aliases_url).json()

                                self.fixing_all_aliases[vulcoid] = self.aliases["aliases"]

                                self.fixing_html_list.append({vulcoid: url_split_id})

                    if "error" in self.all_purls.keys():
                        self.your_search = self.all_purls["error"]

                else:
                    # When do we reach this point?
                    self.your_search = "Not sure -- was your search successful?"

        return render(
            request,
            self.template_name,
            {
                "purl_string": self.purl_string,
                "all_purls": self.all_purls,
                "len_all_purls": self.len_all_purls,
                "all_purls_count": self.all_purls_count,
                "your_search": self.your_search,
                "len_purl_string": self.len_purl_string,
                "results_0": self.results_0,
                "results_0_purl": self.results_0_purl,
                "results_0_type": self.results_0_type,
                "results_0_namespace": self.results_0_namespace,
                "results_0_name": self.results_0_name,
                "results_0_version": self.results_0_version,
                "results_0_qualifiers": self.results_0_qualifiers,
                "results_0_subpath": self.results_0_subpath,
                "affected_by_vulnerabilities": self.affected_by_vulnerabilities,
                "len_affected_by_vulnerabilities": self.len_affected_by_vulnerabilities,
                "fixing_vulnerabilities": self.fixing_vulnerabilities,
                "len_fixing_vulnerabilities": self.len_fixing_vulnerabilities,
                "aliases": self.aliases,
                "all_aliases": self.all_aliases,
                "fixing_all_aliases": self.fixing_all_aliases,
                "affected_html_list": self.affected_html_list,
                "fixing_html_list": self.fixing_html_list,
                "vcio_url_vulnerabilities": self.vcio_url_vulnerabilities,
                "vcio_url_vulnerabilities_string": self.vcio_url_vulnerabilities_string,
            },
        )


# 7/31/2022 Sunday 4:48:56 PM.  Temporary test of older code:
class PurlSearchView02_saved(View):
    # class PurlSearchView02(View):
    template_name = "purl02.html"
    all_purls = {}
    all_packages = {}
    all_packages_results = "N/A"
    all_packages_count = "N/A"
    len_all_purls = "N/A"
    all_purls_count = "N/A"
    purl_string = "N/A"
    len_purl_string = len(purl_string)
    your_search = ""
    results_0 = "N/A"
    results_0_purl = "N/A"
    results_0_type = "N/A"
    results_0_namespace = "N/A"
    results_0_name = "N/A"
    results_0_version = "N/A"
    results_0_qualifiers = "N/A"
    results_0_subpath = "N/A"
    affected_by_vulnerabilities = "N/A"
    len_affected_by_vulnerabilities = "N/A"
    fixing_vulnerabilities = "N/A"
    len_fixing_vulnerabilities = "N/A"
    aliases = "N/A"
    all_aliases = {}
    fixing_all_aliases = {}
    html_list = []
    # above needs renaming to affected_html_list when we refactor
    fixing_html_list = []

    VULNERABLECODE_USER = get_settings("VULNERABLECODE_USER")
    VULNERABLECODE_PASSWORD = get_settings("VULNERABLECODE_PASSWORD")
    VULNERABLECODE_URL = get_settings("VULNERABLECODE_URL", default="")
    VULNERABLECODE_API_URL = get_settings("VULNERABLECODE_API_URL")

    # 7/22/2022 Friday 4:12:18 PM.  Try Philippe's suggestion
    session = requests.Session()
    # session.auth = (user, password)
    session.auth = (VULNERABLECODE_USER, VULNERABLECODE_PASSWORD)
    # response = session.get('http://' + hostname + '/rest/applications')
    # ============================================================

    # 7/21/2022 Thursday 6:25:59 PM.  Redefine this as "vcio_url_vulnerabilities" -- distinguish between packages and vulnerabilities
    # html_url = f"https://{VULNERABLECODE_USER}:{VULNERABLECODE_PASSWORD}@{VULNERABLECODE_URL}vulnerabilities/"
    # 7/22/2022 Friday 4:29:05 PM.  New approach, plus rename
    # html_url = session.get("https://" + VULNERABLECODE_URL + "vulnerabilities/")

    # 7/25/2022 Monday 4:49:56 PM.  This line threw an error after I changed the URL/API_URL session variables to be fully-qualified, i.e., added the `https://` prefix
    # vcio_url_vulnerabilities = session.get("https://" + VULNERABLECODE_URL + "vulnerabilities/")
    # try this:
    # vcio_url_vulnerabilities = session.get(VULNERABLECODE_URL + "vulnerabilities/")
    # ** above needs fixing per Philippe's 7/25/22 suggestion
    # ==========================================================
    vcio_url_vulnerabilities_url = f"{VULNERABLECODE_URL}vulnerabilities/"
    vcio_url_vulnerabilities = session.get(vcio_url_vulnerabilities_url)
    # ==========================================================

    vcio_url_vulnerabilities_string = f"{VULNERABLECODE_URL}vulnerabilities/"

    # 7/22/2022 Friday 10:02:03 AM.  This is the API version:
    # vcio_api_url_vulnerabilities = f"https://{VULNERABLECODE_USER}:{VULNERABLECODE_PASSWORD}@{VULNERABLECODE_API_URL}vulnerabilities/"
    # 7/22/2022 Friday 5:33:40 PM.  The following is throwing errors re concat
    # vcio_api_url_vulnerabilities = session.get(
    #     "https://" + VULNERABLECODE_API_URL + "vulnerabilities/"
    # )
    # 7/25/2022 Monday 4:52:51 PM. Given the new URL/API_URL variables:
    # vcio_api_url_vulnerabilities = session.get(VULNERABLECODE_API_URL + "vulnerabilities/")
    # ** above needs fixing per Philippe's 7/25/22 suggestion
    # ==========================================================
    # 7/26/2022 Tuesday 6:29:14 PM.Looks like the above variable is no longer being used
    # ==========================================================

    # what about this?
    # response = requests.get(uri, auth=(user, password))
    # vcio_api_url_vulnerabilities = requests.get(
    #     f"https://{VULNERABLECODE_API_URL}vulnerabilities/",
    #     auth=({VULNERABLECODE_USER}, {VULNERABLECODE_PASSWORD}),
    # )

    # let's rename this to "vcio_url_packages"
    pkg_html_url = f"{VULNERABLECODE_URL}packages/"

    # 7/21/2022 Thursday 6:40:50 PM.we'll use this 1st variable in the request immediately below

    # 7/22/2022 Friday 6:47:24 PM.  Next: this is next for changing from requests.get to new session.get suggested by Philippe:
    # vcio_api_url_packages_name = f"https://{VULNERABLECODE_USER}:{VULNERABLECODE_PASSWORD}@{VULNERABLECODE_API_URL}packages?name="
    # replace above with:
    # vcio_api_url_packages_name = session.get("https://" + VULNERABLECODE_API_URL + "packages?name=")
    # 7/25/2022 Monday 4:52:51 PM. Given the new URL/API_URL variables:
    # vcio_api_url_packages_name = session.get(VULNERABLECODE_API_URL + "packages?name=")
    # ** above needs fixing per Philippe's 7/25/22 suggestion
    # ==========================================================
    # 7/26/2022 Tuesday 6:14:16 PM.  Looks like we no longer use the above variable
    # ==========================================================

    # vcio_api_url_packages_purl = f"https://{VULNERABLECODE_USER}:{VULNERABLECODE_PASSWORD}@{VULNERABLECODE_API_URL}packages?purl="
    # replace above with:
    # vcio_api_url_packages_purl = session.get("https://" + VULNERABLECODE_API_URL + "packages?purl=")
    # 7/25/2022 Monday 4:52:51 PM. Given the new URL/API_URL variables:
    # vcio_api_url_packages_purl = session.get(VULNERABLECODE_API_URL + "packages?purl=")
    # ** above needs fixing per Philippe's 7/25/22 suggestion
    # ==========================================================
    # 7/26/2022 Tuesday 6:14:16 PM.  Looks like we no longer use the above variable
    # ==========================================================

    packageid = "N/A"
    packageid_dict = {}

    def get(self, request):
        if "category" in request.GET and request.GET["category"] == "package":
            if "purl_string" in request.GET and request.GET["purl_string"] != "":
                self.your_search = request.GET["purl_string"]

                # self.all_packages = requests.get(
                #     self.vcio_api_url_packages_name
                #     + request.GET["purl_string"]
                #     + "&type=&version=&subpath=&purl="
                # ).json()

                # try this:
                # self.all_packages = self.session.get(
                #     "https://"
                #     + self.VULNERABLECODE_API_URL
                #     + "packages?name="
                #     + request.GET["purl_string"]
                # ).json()
                # 7/25/2022 Monday 4:52:51 PM. Given the new URL/API_URL variables:
                # self.all_packages = self.session.get(
                #     self.VULNERABLECODE_API_URL + "packages?name=" + request.GET["purl_string"]
                # ).json()
                # ** above needs fixing per Philippe's 7/25/22 suggestion
                # ==========================================================
                all_packages_url = f"{self.VULNERABLECODE_API_URL}packages?name={self.your_search}"
                self.all_packages = self.session.get(all_packages_url).json()
                # ==========================================================

                # # 7/25/2022 Monday 10:56:28 AM.  Per Philippe's comment re self.aliases, making similar change here:
                # VULNERABLECODE_API_URL = "https://public.vulnerablecode.io/api"
                # package_name = request.GET["purl_string"]
                # # aliases_url = f"{VULNERABLECODE_API_URL}/vulnerabilities/{url_split_id}"
                # package_url = f"{VULNERABLECODE_API_URL}/packages?name=/{package_name}"
                # # self.aliases = self.session.get(aliases_url).json()
                # self.all_packages = self.session.get(package_url).json()

                if self.all_packages["count"] != 0:
                    pass
                else:
                    self.your_search = (
                        "The VCIO DB does not contain a record of the package name you entered -- "
                        + request.GET["purl_string"]
                    )
                    return render(
                        request,
                        # "home02.html",
                        "index_new.html",
                        {
                            "your_search": self.your_search,
                            "form": forms.CVEForm(request.GET or None),
                        },
                    )

            else:
                self.your_search = (
                    "Please select 'package' from the dropdown and add a value to the search box."
                )
                return render(
                    request,
                    # "home02.html",
                    "index_new.html",
                    {
                        "your_search": self.your_search,
                        "form": forms.CVEForm(request.GET or None),
                    },
                )
            self.all_packages_results = self.all_packages["results"]

            self.all_packages_count = self.all_packages["count"]
            self.packageid_dict = {}
            for pkg in self.all_packages_results:
                self.packageid = pkg["url"].rsplit("/", 1)[-1]
                self.packageid_dict[pkg["purl"]] = self.packageid

            return render(
                request,
                "packages01.html",
                {
                    "your_search": self.your_search,
                    "all_packages": self.all_packages,
                    "all_packages_results": self.all_packages_results,
                    "all_packages_count": self.all_packages_count,
                    "packageid": self.packageid,
                    "packageid_dict": self.packageid_dict,
                    "pkg_html_url": self.pkg_html_url,
                },
            )

        if "purl_string" in request.GET:
            self.purl_string = request.GET["purl_string"]
            if len(self.purl_string) == 0:
                self.your_search = "Please add a value to the search box."
                return render(
                    request,
                    # "home02.html",
                    "index_new.html",
                    {
                        "your_search": self.your_search,
                        "form": forms.CVEForm(request.GET or None),
                    },
                )
            else:
                self.your_search = request.GET["purl_string"]

                # Test whether input is a valid purl.
                try:
                    PackageURL.from_string(self.purl_string)
                except Exception as e:
                    self.your_search = (
                        "Your input is not a syntactically valid purl -- "
                        + str(e)
                        + " \r\rIf you're searching by package name rather than purl, please make sure you select 'package' from the dropdown and then add your package name to the search box."
                    )
                    return render(
                        request,
                        # "home02.html",
                        "index_new.html",
                        {
                            "your_search": self.your_search,
                            "form": forms.CVEForm(request.GET or None),
                        },
                    )

                # self.all_purls = requests.get(
                #     self.vcio_api_url_packages_purl
                #     + self.purl_string
                #     # + a_type
                #     # + "&name="
                #     # + a_name
                # ).json()

                # try this:
                # self.all_purls = self.session.get(
                #     "https://" + self.VULNERABLECODE_API_URL + "packages?purl=" + self.purl_string
                # ).json()

                # 7/25/2022 Monday 4:52:51 PM. Given the new URL/API_URL variables:
                # self.all_purls = self.session.get(
                #     self.VULNERABLECODE_API_URL + "packages?purl=" + self.purl_string
                # ).json()
                # ** above needs fixing per Philippe's 7/25/22 suggestion
                # ==========================================================
                all_purls_url = f"{self.VULNERABLECODE_API_URL}packages?purl={self.purl_string}"
                self.all_purls = self.session.get(all_purls_url).json()
                # ==========================================================

                if self.all_purls:
                    self.len_all_purls = len(self.all_purls)
                    if "count" in self.all_purls.keys():
                        self.all_purls_count = self.all_purls["count"]
                        if self.all_purls_count == 0:
                            self.your_search = (
                                "The VCIO DB does not contain a record of the purl you entered -- "
                                + request.GET["purl_string"]
                            )
                            return render(
                                request,
                                # "home02.html",
                                "index_new.html",
                                {
                                    "your_search": self.your_search,
                                    "form": forms.CVEForm(request.GET or None),
                                },
                            )
                        elif self.all_purls_count == 1:
                            self.results_0 = self.all_purls["results"][0]
                            self.results_0_purl = self.results_0["purl"]
                            self.results_0_type = self.results_0["type"]
                            self.results_0_namespace = self.results_0["namespace"]
                            self.results_0_name = self.results_0["name"]
                            self.results_0_version = self.results_0["version"]
                            self.results_0_qualifiers = self.results_0["qualifiers"]
                            self.results_0_subpath = self.results_0["subpath"]
                            self.affected_by_vulnerabilities = self.results_0[
                                "affected_by_vulnerabilities"
                            ]
                            self.fixing_vulnerabilities = self.results_0["fixing_vulnerabilities"]
                            self.len_affected_by_vulnerabilities = len(
                                self.affected_by_vulnerabilities
                            )
                            self.len_fixing_vulnerabilities = len(self.fixing_vulnerabilities)

                            self.all_aliases = {}
                            self.html_list = []
                            for vuln in self.affected_by_vulnerabilities:
                                url_split_id = vuln["url"].rsplit("/", 1)[-1]
                                vulcoid = vuln["vulnerability_id"]
                                # 7/16/2022 Saturday 1:49:21 PM.  Will clearing the dict and list fix the problem?  No -- this only handles the last of a group of VULCOIDs. so maybe do this just above the "for"?
                                # self.all_aliases = {}
                                # self.html_list = []
                                # end of attempted fix
                                # next

                                # 7/22/2022 Friday 6:10:24 PM.  With the new session API approach Philippe suggested, this throws an error
                                # TypeError: unsupported operand type(s) for +: 'Response' and 'str'
                                # so let's rewrite and try
                                # self.aliases = requests.get(
                                #     # 7/22/2022 Friday 10:05:12 AM.  Replace API URL:
                                #     self.vcio_api_url_vulnerabilities
                                #     + url_split_id
                                # ).json()

                                # try this:
                                # self.aliases = self.session.get(
                                #     "https://"
                                #     + self.VULNERABLECODE_API_URL
                                #     + "vulnerabilities/"
                                #     + url_split_id
                                # ).json()

                                # 7/25/2022 Monday 4:52:51 PM. Given the new URL/API_URL variables:
                                # self.aliases = self.session.get(
                                #     self.VULNERABLECODE_API_URL + "vulnerabilities/" + url_split_id
                                # ).json()
                                # ** above needs fixing per Philippe's 7/25/22 suggestion
                                # ==========================================================
                                aliases_url = (
                                    f"{self.VULNERABLECODE_API_URL}vulnerabilities/{url_split_id}"
                                )
                                self.aliases = self.session.get(aliases_url).json()
                                # ==========================================================

                                # # 7/25/2022 Monday 10:12:19 AM.  Per comment from Philippe, do this instead:
                                # VULNERABLECODE_API_URL = "https://public.vulnerablecode.io/api"
                                # aliases_url = (
                                #     f"{VULNERABLECODE_API_URL}/vulnerabilities/{url_split_id}"
                                # )
                                # self.aliases = self.session.get(aliases_url).json()

                                # all_aliases[vulcoid] = aliases
                                self.all_aliases[vulcoid] = self.aliases["aliases"]
                                # html_list.append(url_split_id)
                                self.html_list.append({vulcoid: url_split_id})

                            # 7/17/2022 Sunday 11:54:26 AM.  Above needs to be renamed and of course refactored -- no refactoring yet!
                            # But can we also do the same for fixing vulnerabilities?  Let's try.
                            self.fixing_all_aliases = {}
                            self.fixing_html_list = []
                            for vuln in self.fixing_vulnerabilities:
                                url_split_id = vuln["url"].rsplit("/", 1)[-1]
                                vulcoid = vuln["vulnerability_id"]

                                # 7/22/2022 Friday 6:18:08 PM.  Need to use session.get in place of requests.get
                                # self.aliases = requests.get(
                                #     # 7/22/2022 Friday 10:05:12 AM.  Replace API URL:
                                #     self.vcio_api_url_vulnerabilities
                                #     + url_split_id
                                # ).json()

                                # try this:
                                # self.aliases = self.session.get(
                                #     "https://"
                                #     + self.VULNERABLECODE_API_URL
                                #     + "vulnerabilities/"
                                #     + url_split_id
                                # ).json()

                                # 7/25/2022 Monday 4:52:51 PM. Given the new URL/API_URL variables:
                                # self.aliases = self.session.get(
                                #     self.VULNERABLECODE_API_URL + "vulnerabilities/" + url_split_id
                                # ).json()
                                # ** above needs fixing per Philippe's 7/25/22 suggestion
                                # ==========================================================
                                aliases_url = (
                                    f"{self.VULNERABLECODE_API_URL}vulnerabilities/{url_split_id}"
                                )
                                self.aliases = self.session.get(aliases_url).json()
                                # ==========================================================

                                # 7/25/2022 Monday 10:12:19 AM.  Per comment from Philippe, as with the similar code just above, do this instead:

                                # VULNERABLECODE_API_URL = "https://public.vulnerablecode.io/api"
                                # aliases_url = (
                                #     f"{VULNERABLECODE_API_URL}/vulnerabilities/{url_split_id}"
                                # )
                                # self.aliases = self.session.get(aliases_url).json()

                                # self.all_aliases[vulcoid] = self.aliases["aliases"]
                                self.fixing_all_aliases[vulcoid] = self.aliases["aliases"]
                                # self.html_list.append({vulcoid: url_split_id})
                                self.fixing_html_list.append({vulcoid: url_split_id})

                    if "error" in self.all_purls.keys():
                        self.your_search = self.all_purls["error"]

                else:
                    # When do we reach this point?
                    self.your_search = "Not sure -- was your search successful?"

        return render(
            request,
            self.template_name,
            {
                "purl_string": self.purl_string,
                "all_purls": self.all_purls,
                "len_all_purls": self.len_all_purls,
                "all_purls_count": self.all_purls_count,
                "your_search": self.your_search,
                "len_purl_string": self.len_purl_string,
                "results_0": self.results_0,
                "results_0_purl": self.results_0_purl,
                "results_0_type": self.results_0_type,
                "results_0_namespace": self.results_0_namespace,
                "results_0_name": self.results_0_name,
                "results_0_version": self.results_0_version,
                "results_0_qualifiers": self.results_0_qualifiers,
                "results_0_subpath": self.results_0_subpath,
                "affected_by_vulnerabilities": self.affected_by_vulnerabilities,
                "len_affected_by_vulnerabilities": self.len_affected_by_vulnerabilities,
                "fixing_vulnerabilities": self.fixing_vulnerabilities,
                "len_fixing_vulnerabilities": self.len_fixing_vulnerabilities,
                "aliases": self.aliases,
                "all_aliases": self.all_aliases,
                "fixing_all_aliases": self.fixing_all_aliases,
                "html_list": self.html_list,
                "fixing_html_list": self.fixing_html_list,
                "vcio_url_vulnerabilities": self.vcio_url_vulnerabilities,
                "vcio_url_vulnerabilities_string": self.vcio_url_vulnerabilities_string,
            },
        )
