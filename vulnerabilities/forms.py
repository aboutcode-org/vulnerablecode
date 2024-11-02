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

from .models import *


class PaginationForm(forms.Form):
    """Form to handle page size selection across the application."""

    PAGE_CHOICES = [
        ("20", "20 per page"),
        ("50", "50 per page"),
        ("100", "100 per page"),
    ]

    page_size = forms.ChoiceField(
        choices=PAGE_CHOICES,
        initial="20",
        required=False,
        widget=forms.Select(
            attrs={
                "class": "select is-small",
                "onchange": "handlePageSizeChange(this.value)",
                "id": "page-size-select",
            }
        ),
    )


class BaseSearchForm(forms.Form):
    """Base form for implementing search functionality."""

    search = forms.CharField(required=True)

    def clean_search(self):
        return self.cleaned_data.get("search", "")

    def get_queryset(self, query=None):
        """
        Get queryset with search/filter/ordering applied.
        Args:
            query (str, optional): Direct query for testing
        """
        if query is not None:
            return self._search(query)

        if not self.is_valid():
            return self.model.objects.none()

        return self._search(self.clean_search())


class PackageSearchForm(BaseSearchForm):
    model = Package
    search = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={"placeholder": "Package name, purl or purl fragment"},
        ),
    )

    def _search(self, query):
        """Execute package-specific search logic."""
        return (
            self.model.objects.search(query)
            .with_vulnerability_counts()
            .prefetch_related()
            .order_by("package_url")
        )


class VulnerabilitySearchForm(BaseSearchForm):
    model = Vulnerability
    search = forms.CharField(
        required=True,
        widget=forms.TextInput(
            attrs={"placeholder": "Vulnerability id or alias such as CVE or GHSA"}
        ),
    )

    def _search(self, query):
        """Execute vulnerability-specific search logic."""
        return self.model.objects.search(query=query).with_package_counts()


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
        email_field = self.fields["email"]
        first_name_field = self.fields["first_name"]
        last_name_field = self.fields["last_name"]
        email_field.required = True
        email_field.label = "Email"
        email_field.widget.attrs["class"] = "input"
        email_field.widget.attrs["style"] = "width: 50%"
        email_field.widget.attrs["placeholder"] = "foo@bar.com"
        first_name_field.label = "First Name"
        first_name_field.widget.attrs["class"] = "input"
        first_name_field.widget.attrs["style"] = "width: 50%"
        first_name_field.widget.attrs["placeholder"] = "Jon"
        last_name_field.label = "Last Name"
        last_name_field.widget.attrs["class"] = "input"
        last_name_field.widget.attrs["style"] = "width: 50%"
        last_name_field.widget.attrs["placeholder"] = "Doe"

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
