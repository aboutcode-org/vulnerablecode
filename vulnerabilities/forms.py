#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django import forms

from vulnerabilities.models import Package


def get_known_package_types():
    """
    Return a list of known package types.
    """
    pkg_types = [(i.type, i.type) for i in Package.objects.distinct("type").all()]
    pkg_types.append((None, "Any type"))
    return pkg_types


class PackageForm(forms.Form):

    search = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={"placeholder": "Package name, purl or purl fragment"},
        ),
    )


class VulnerabilityForm(forms.Form):

    search = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={"placeholder": "Vulnerability id or alias such as CVE or GHSA"}
        ),
    )
