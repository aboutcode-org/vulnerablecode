#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

from review.models import Note
from review.models import Repository
from review.models import Review


class CreateGitRepoForm(forms.ModelForm):
    class Meta:
        model = Repository
        fields = ["name", "url"]

    def __init__(self, *args, **kwargs):
        super(CreateGitRepoForm, self).__init__(*args, **kwargs)
        self.fields["name"].widget.attrs.update({"class": "input mb-5"})
        self.fields["url"].widget.attrs.update({"class": "input mb-5"})


class CreateNoteForm(forms.ModelForm):
    class Meta:
        model = Note
        fields = ["content"]

    def __init__(self, *args, **kwargs):
        super(CreateNoteForm, self).__init__(*args, **kwargs)
        self.fields["content"].widget.attrs.update(
            {"class": "textarea", "placeholder": "Add a note...", "rows": 5}
        )
        self.fields["content"].label = ""


class ReviewStatusForm(forms.ModelForm):
    class Meta:
        model = Review
        fields = ["status"]

    def __init__(self, *args, **kwargs):
        super(ReviewStatusForm, self).__init__(*args, **kwargs)
        self.fields["status"].widget.attrs.update({"class": "input mb-5"})


class PersonSignUpForm(UserCreationForm):
    email = forms.EmailField(max_length=254)

    class Meta:
        model = User
        fields = (
            "username",
            "email",
            "password1",
            "password2",
        )


class CreateReviewForm(forms.Form):
    headline = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "input is-medium title has-text-centered",
                "placeholder": "Review Title",
            }
        )
    )
    data = forms.CharField(widget=forms.Textarea(attrs={"class": "textarea", "rows": 16}))
    filename = forms.CharField(widget=forms.HiddenInput())


class FetchForm(forms.Form):
    file_path = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "input",
                "placeholder": "alpine/dia/VCID-xxx-xxx-xxx.yaml",
            }
        )
    )


class SubscribePurlForm(forms.Form):
    acct = forms.CharField(
        label="Subscribe with a remote account:",
        widget=forms.TextInput(
            attrs={"placeholder": "ziadhany@vulnerablecode.io", "class": "input"}
        ),
    )


class SearchPurlForm(forms.Form):
    search = forms.CharField(
        required=True,
        label=False,
        widget=forms.TextInput(
            attrs={
                "placeholder": "Please entre a valid purl ex: pkg:maven/org.apache.commons/io@1.3.4",
                "class": "input is-rounded",
                "style": "width: 90%;",
            },
        ),
    )


class SearchReviewForm(forms.Form):
    search = forms.CharField(
        required=True,
        label=False,
        widget=forms.TextInput(
            attrs={
                "placeholder": "Please Entre a valid Review Name",
                "class": "input is-rounded",
                "style": "width: 90%;",
            },
        ),
    )


class SearchRepositoryForm(forms.Form):
    search = forms.CharField(
        required=True,
        label=False,
        widget=forms.TextInput(
            attrs={
                "placeholder": "Please Entre a Repository URL ex: https://github.com/nexB/vulnerablecode-data",
                "class": "input is-rounded",
                "style": "width: 90%;",
            },
        ),
    )
