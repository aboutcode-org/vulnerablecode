#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.contrib import admin
from django.urls import include
from django.urls import path
from rest_framework.routers import DefaultRouter

from vulnerabilities.api import AliasViewSet
from vulnerabilities.api import CPEViewSet
from vulnerabilities.api import PackageViewSet
from vulnerabilities.api import VulnerabilityViewSet
from vulnerabilities.views import HomePage
from vulnerabilities.views import PackageDetails
from vulnerabilities.views import PackageSearchView
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
api_router.register(r"cpes", CPEViewSet, basename="cpe")
api_router.register(r"alias", AliasViewSet, basename="alias")

urlpatterns = [
    path("", HomePage.as_view(), name="home"),
    path("packages/search", PackageSearchView.as_view(), name="package_search"),
    path("packages/<int:pk>", PackageDetails.as_view(), name="package_view"),
    path("vulnerabilities/search", VulnerabilitySearchView.as_view(), name="vulnerability_search"),
    path(
        "vulnerabilities/<str:vulnerability_id>",
        VulnerabilityDetails.as_view(),
        name="vulnerability_view",
    ),
    path("api/docs", schema_view, name="redoc"),
    path(r"api/", include(api_router.urls)),
    # disabled for now
    #    path("admin/", admin.site.urls),
]
