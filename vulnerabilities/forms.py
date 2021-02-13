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
#  VulnerableCode is a free software tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from django import forms

from vulnerabilities.models import Package, PackageRelatedVulnerability, Vulnerability


def get_package_types():
    pkg_types = [(i.type, i.type) for i in Package.objects.distinct("type").all()]
    pkg_types.append((None, "Any type"))
    return pkg_types


def get_package_namespaces():
    pkg_namespaces = [
        (i.namespace, i.namespace)
        for i in Package.objects.distinct("namespace").all()
        if i.namespace
    ]
    pkg_namespaces.append((None, "package namespace"))
    return pkg_namespaces


class PackageForm(forms.Form):

    type = forms.ChoiceField(choices=get_package_types)
    name = forms.CharField(
        required=False, widget=forms.TextInput(attrs={"placeholder": "package name"})
    )


class CVEForm(forms.Form):

    vuln_id = forms.CharField(widget=forms.TextInput(attrs={"placeholder": "vulnerability id"}))
