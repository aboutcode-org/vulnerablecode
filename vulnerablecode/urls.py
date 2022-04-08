#
# Copyright (c) nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an 'AS IS' BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from django.contrib import admin
from django.urls import include
from django.urls import path
from rest_framework.routers import DefaultRouter

from vulnerabilities.api import PackageViewSet
from vulnerabilities.api import VulnerabilityViewSet
from vulnerabilities.views import HomePage
from vulnerabilities.views import PackageSearchView
from vulnerabilities.views import PackageUpdate
from vulnerabilities.views import VulnerabilityDetails
from vulnerabilities.views import VulnerabilitySearchView
from vulnerabilities.views import schema_view


# See the comment at https://stackoverflow.com/a/46163870.
class OptionalSlashRouter(DefaultRouter):

    def __init__(self, *args, **kwargs):
        super(DefaultRouter, self).__init__(*args, **kwargs)
        self.trailing_slash = "/?"


api_router = OptionalSlashRouter()
api_router.register(r"packages", PackageViewSet)
# `DefaultRouter` requires `basename` when registering viewsets that don't define a queryset.
api_router.register(r"vulnerabilities", VulnerabilityViewSet, basename="vulnerability")

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/docs", schema_view, name="redoc"),
    path("packages/search", PackageSearchView.as_view(), name="package_search"),
    path("packages/<int:pk>", PackageUpdate.as_view(), name="package_view"),
    path("vulnerabilities/<int:pk>", VulnerabilityDetails.as_view(), name="vulnerability_view"),
    path("vulnerabilities/search", VulnerabilitySearchView.as_view(), name="vulnerability_search"),
    path("", HomePage.as_view(), name="home"),
    path(r"api/", include(api_router.urls)),
]

