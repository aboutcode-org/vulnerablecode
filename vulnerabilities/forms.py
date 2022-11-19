#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django import forms
from django.core.validators import validate_email

from vulnerabilities.models import ApiUser


class PackageSearchForm(forms.Form):

    search = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={"placeholder": "Package name, purl or purl fragment"},
        ),
    )


class VulnerabilitySearchForm(forms.Form):

    search = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={"placeholder": "Vulnerability id or alias such as CVE or GHSA"}
        ),
    )


class ApiUserCreationForm(forms.ModelForm):
    """
    Support a simplified creation for API-only users directly from the UI.
    """

    class Meta:
        model = ApiUser
        fields = (
            "email",
            "first_name",
            "last_name",
        )

    def __init__(self, *args, **kwargs):
        super(ApiUserCreationForm, self).__init__(*args, **kwargs)
        self.fields["email"].required = True

    def save(self, commit=True):
        return ApiUser.objects.create_api_user(
            username=self.cleaned_data["email"],
            first_name=self.cleaned_data["first_name"],
            last_name=self.cleaned_data["last_name"],
        )

    def clean_username(self):
        username = self.cleaned_data["email"]
        validate_email(username)
        return username

    def save_m2m(self):
        pass
