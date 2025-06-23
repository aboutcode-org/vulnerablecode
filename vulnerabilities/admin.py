#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django import forms
from django.contrib import admin
from django.contrib.admin.widgets import FilteredSelectMultiple
from django.contrib.auth.admin import GroupAdmin as BasicGroupAdmin
from django.contrib.auth.models import Group
from django.contrib.auth.models import User
from django.core.validators import validate_email

from vulnerabilities.models import ApiUser
from vulnerabilities.models import Package
from vulnerabilities.models import Vulnerability
from vulnerabilities.models import VulnerabilityReference
from vulnerabilities.models import VulnerabilitySeverity

admin.site.site_header = "VulnerableCode Administration"
admin.site.site_title = "VulnerableCode Admin Portal"
admin.site.index_title = "Welcome to VulnerableCode Management"


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    search_fields = ["vulnerability_id"]


@admin.register(VulnerabilityReference)
class VulnerabilityReferenceAdmin(admin.ModelAdmin):
    search_fields = ["vulnerabilityrelatedreference__vulnerability__id", "reference_id", "url"]


@admin.register(Package)
class PackageAdmin(admin.ModelAdmin):
    list_filter = ("type", "namespace")
    search_fields = ["name"]


@admin.register(VulnerabilitySeverity)
class VulnerabilitySeverityAdmin(admin.ModelAdmin):
    pass


class ApiUserCreationForm(forms.ModelForm):
    """
    This helps have a simplified creation for API-only users in the admin
    """

    class Meta:
        model = ApiUser
        fields = (
            "username",
            "first_name",
            "last_name",
        )

    def save(self, commit=True):
        return ApiUser.objects.create_api_user(
            username=self.cleaned_data["username"],
            first_name=self.cleaned_data["first_name"],
            last_name=self.cleaned_data["last_name"],
        )

    def clean_username(self):
        username = self.cleaned_data["username"]
        validate_email(username)
        return username

    def save_m2m(self):
        pass


@admin.register(ApiUser)
class ApiUserAdmin(admin.ModelAdmin):
    list_display = ("username", "email", "first_name", "last_name", "is_staff")
    list_filter = ("username", "email", "first_name", "last_name", "is_staff")
    search_fields = ("username", "email", "first_name", "last_name")
    fieldsets = (
        (
            None,
            {
                "fields": (
                    "username",
                    "first_name",
                    "last_name",
                )
            },
        ),
    )

    add_form = ApiUserCreationForm

    def get_form(self, request, obj=None, **kwargs):
        """
        Use special form during user creation
        """
        defaults = {}
        if obj is None:
            defaults["form"] = self.add_form
        defaults.update(kwargs)
        return super().get_form(request, obj, **defaults)


class GroupWithUsersForm(forms.ModelForm):
    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.all(),
        required=False,
        widget=FilteredSelectMultiple("Users", is_stacked=False),
        label="Users",
    )

    class Meta:
        model = Group
        fields = "__all__"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["users"].label_from_instance = lambda user: (
            f"{user.username} | {user.email}" if user.email else user.username
        )
        if self.instance.pk:
            self.fields["users"].initial = self.instance.user_set.all()

    def save(self, commit=True):
        group = super().save(commit=commit)
        self.save_m2m()
        group.user_set.set(self.cleaned_data["users"])
        return group


admin.site.unregister(Group)


@admin.register(Group)
class GroupAdmin(admin.ModelAdmin):
    form = GroupWithUsersForm
    search_fields = ("name",)
    ordering = ("name",)
    filter_horizontal = ("permissions",)

    def formfield_for_manytomany(self, db_field, request=None, **kwargs):
        if db_field.name == "permissions":
            qs = kwargs.get("queryset", db_field.remote_field.model.objects)
            # Avoid a major performance hit resolving permission names which
            # triggers a content_type load:
            kwargs["queryset"] = qs.select_related("content_type")
        return super().formfield_for_manytomany(db_field, request=request, **kwargs)
