# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from urllib.parse import urlencode

from django.core.paginator import Paginator
from django.http import HttpResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.views import View
from django.views.generic.list import ListView
from django.views.generic.edit import UpdateView
from django.views.generic.edit import CreateView
from django.views.generic.edit import DeleteView


from vulnerabilities import forms
from vulnerabilities import models
from vulnerablecode.settings import ENABLE_CURATION


class PackageSearchView(View):
    template_name = "packages.html"

    def get(self, request):
        context = {"form": forms.PackageForm(request.GET or None)}

        if request.GET:
            packages = self.request_to_queryset(request)
            result_size = packages.count()
            page_no = int(request.GET.get("page", 1))
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

        return models.Package.objects.all().filter(
            name__icontains=package_name,
            type__icontains=package_type,
        )


class VulnerabilitySearchView(View):

    template_name = "vulnerabilities.html"

    def get(self, request):
        context = {"form": forms.CVEForm(request.GET or None)}
        if request.GET:
            vulnerabilities = self.request_to_queryset(request)
            result_size = vulnerabilities.count()
            pages = Paginator(vulnerabilities, 50)
            vulnerabilities = pages.get_page(int(self.request.GET.get("page", 1)))
            context["vulnerabilities"] = vulnerabilities
            context["result_size"] = result_size

        return render(request, self.template_name, context)

    @staticmethod
    def request_to_queryset(request):
        vuln_id = request.GET["vuln_id"]
        return models.Vulnerability.objects.filter(vulnerability_id__icontains=vuln_id)


class PackageUpdate(UpdateView):

    template_name = "package_update.html"
    model = models.Package
    fields = ["name", "type", "version", "namespace"]

    def get_context_data(self, **kwargs):
        context = super(PackageUpdate, self).get_context_data(**kwargs)
        resolved_vuln, unresolved_vuln = self._package_vulnerabilities(self.kwargs["pk"])
        context["resolved_vuln"] = resolved_vuln
        context["impacted_vuln"] = unresolved_vuln
        context["enable_curation"] = ENABLE_CURATION

        return context

    def _package_vulnerabilities(self, package_pk):

        resolved_vuln = [i for i in self.get_object().resolved_to]
        unresolved_vuln = [i for i in self.get_object().vulnerable_to]

        return resolved_vuln, unresolved_vuln

    def get_success_url(self):
        return reverse("package_view", kwargs={"pk": self.kwargs["pk"]})


class VulnerabilityDetails(ListView):
    template_name = "vulnerability.html"
    model = models.VulnerabilityReference

    def get_context_data(self, **kwargs):
        context = super(VulnerabilityDetails, self).get_context_data(**kwargs)
        context["vulnerability"] = models.Vulnerability.objects.get(id=self.kwargs["pk"])
        context["enable_curation"] = ENABLE_CURATION
        return context

    def get_queryset(self):
        return models.VulnerabilityReference.objects.filter(vulnerability_id=self.kwargs["pk"])


class VulnerabilityCreate(CreateView):

    template_name = "vulnerability_create.html"
    model = models.Vulnerability
    fields = ["vulnerability_id", "summary"]

    def get_success_url(self):

        return reverse("vulnerability_view", kwargs={"pk": self.object.id})


class PackageCreate(CreateView):

    template_name = "package_create.html"
    model = models.Package
    fields = ["name", "namespace", "type", "version"]

    def get_success_url(self):
        return reverse("package_view", kwargs={"pk": self.object.id})


class PackageRelatedVulnerablityDelete(DeleteView):
    model = models.PackageRelatedVulnerability

    def get_object(self):
        package_id = self.kwargs.get("pid")
        vulnerability_id = self.kwargs.get("vid")
        return models.PackageRelatedVulnerability.objects.get(
            package_id=package_id, vulnerability_id=vulnerability_id
        )

    def get_success_url(self):
        return reverse("package_view", kwargs={"pk": self.kwargs.get("pid")})


class HomePage(View):

    template_name = "index.html"

    def get(self, request):
        return render(request, self.template_name, context={"enable_curation": ENABLE_CURATION})


class PackageRelatedVulnerablityCreate(View):

    template_name = "packagerelatedvulnerability_create.html"

    def get(self, request, *args, **kwargs):
        context = {"form": forms.CVEForm()}
        return render(request, self.template_name, context=context)

    def post(self, request, *args, **kwargs):
        if "vuln_id" in self.request.POST:
            is_vulnerable = "impacted" in self.request.headers["Referer"]
            relation = self.create_relationship_instance(
                vulnerability_id=self.request.POST["vuln_id"],
                package_id=kwargs["pid"],
                is_vulnerable=is_vulnerable,
            )

            if self.relationship_already_exists(relation):
                return HttpResponse(
                    "The package already has relationship with the provided vulnerability"
                )

            relation.save()
            return redirect(reverse("package_view", kwargs={"pk": self.kwargs.get("pid")}))

    @staticmethod
    def relationship_already_exists(relationship):
        existing_relation = models.PackageRelatedVulnerability.objects.filter(
            package=relationship.package, vulnerability=relationship.vulnerability
        )
        return existing_relation.exists()

    @staticmethod
    def create_relationship_instance(vulnerability_id, package_id, is_vulnerable):
        package = models.Package.objects.get(id=package_id)
        vulnerability, vuln_created = models.Vulnerability.objects.get_or_create(
            vulnerability_id=vulnerability_id
        )  # nopep8
        return models.PackageRelatedVulnerability(
            vulnerability=vulnerability, package=package, is_vulnerable=is_vulnerable
        )


class VulnerabilityReferenceCreate(CreateView):

    template_name = "vulnerability_reference_create.html"
    model = models.VulnerabilityReference
    fields = ["reference_id", "url"]

    def form_valid(self, form):
        form.instance.vulnerability = models.Vulnerability.objects.get(id=self.kwargs["vid"])
        return super(VulnerabilityReferenceCreate, self).form_valid(form)

    def get_success_url(self):
        return reverse("vulnerability_view", kwargs={"pk": self.kwargs["vid"]})
