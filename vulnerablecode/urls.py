#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.contrib import admin
from django.urls import include
from django.urls import path
from django.urls import re_path
from django.views.generic import TemplateView
from drf_spectacular.views import SpectacularAPIView
from drf_spectacular.views import SpectacularSwaggerView
from rest_framework.routers import DefaultRouter

from vulnerabilities.api import AliasViewSet
from vulnerabilities.api import CPEViewSet
from vulnerabilities.api import PackageViewSet
from vulnerabilities.api import VulnerabilityViewSet
from vulnerabilities.api_v2 import CodeFixViewSet
from vulnerabilities.api_v2 import PackageV2ViewSet
from vulnerabilities.api_v2 import PipelineScheduleV2ViewSet
from vulnerabilities.api_v2 import VulnerabilityV2ViewSet
from vulnerabilities.views import AdminLoginView
from vulnerabilities.views import ApiUserCreateView
from vulnerabilities.views import HomePage
from vulnerabilities.views import PackageDetails
from vulnerabilities.views import PackageSearch
from vulnerabilities.views import PipelineRunDetailView
from vulnerabilities.views import PipelineRunListView
from vulnerabilities.views import PipelineScheduleListView
from vulnerabilities.views import VulnerabilityDetails
from vulnerabilities.views import VulnerabilityPackagesDetails
from vulnerabilities.views import VulnerabilitySearch
from vulnerablecode.settings import DEBUG
from vulnerablecode.settings import DEBUG_TOOLBAR


# See the comment at https://stackoverflow.com/a/46163870.
class OptionalSlashRouter(DefaultRouter):
    def __init__(self, *args, **kwargs):
        super(DefaultRouter, self).__init__(*args, **kwargs)
        self.trailing_slash = "/?"


api_router = OptionalSlashRouter()
api_router.register("packages", PackageViewSet)
# `DefaultRouter` requires `basename` when registering viewsets that don't define a queryset.
api_router.register("vulnerabilities", VulnerabilityViewSet, basename="vulnerability")
api_router.register("cpes", CPEViewSet, basename="cpe")
api_router.register("aliases", AliasViewSet, basename="alias")

api_v2_router = OptionalSlashRouter()
api_v2_router.register("packages", PackageV2ViewSet, basename="package-v2")
api_v2_router.register("vulnerabilities", VulnerabilityV2ViewSet, basename="vulnerability-v2")
api_v2_router.register("codefixes", CodeFixViewSet, basename="codefix")
api_v2_router.register("schedule", PipelineScheduleV2ViewSet, basename="schedule")


urlpatterns = [
    path("admin/login/", AdminLoginView.as_view(), name="admin-login"),
    path("api/v2/", include(api_v2_router.urls)),
    path(
        "robots.txt",
        TemplateView.as_view(template_name="robots.txt", content_type="text/plain"),
    ),
    path(
        "",
        HomePage.as_view(),
        name="home",
    ),
    path(
        "pipelines/schedule/",
        PipelineScheduleListView.as_view(),
        name="schedule",
    ),
    path(
        "pipelines/<str:pipeline_id>/runs/",
        PipelineRunListView.as_view(),
        name="runs-list",
    ),
    path(
        "pipelines/<str:pipeline_id>/run/<uuid:run_id>/",
        PipelineRunDetailView.as_view(),
        name="run-details",
    ),
    path(
        "packages/search/",
        PackageSearch.as_view(),
        name="package_search",
    ),
    re_path(
        r"^packages/(?P<purl>pkg:.+)$",
        PackageDetails.as_view(),
        name="package_details",
    ),
    path(
        "vulnerabilities/search/",
        VulnerabilitySearch.as_view(),
        name="vulnerability_search",
    ),
    path(
        "vulnerabilities/<str:vulnerability_id>",
        VulnerabilityDetails.as_view(),
        name="vulnerability_details",
    ),
    path(
        "vulnerabilities/<str:vulnerability_id>/packages",
        VulnerabilityPackagesDetails.as_view(),
        name="vulnerability_package_details",
    ),
    path(
        "api/",
        include(api_router.urls),
        name="api",
    ),
    path(
        "api/schema/",
        SpectacularAPIView.as_view(),
        name="schema",
    ),
    path(
        "api/docs/",
        SpectacularSwaggerView.as_view(url_name="schema"),
        name="api_docs",
    ),
    path(
        "account/request_api_key/",
        ApiUserCreateView.as_view(),
        name="api_user_request",
    ),
    path(
        "tos/",
        TemplateView.as_view(template_name="tos.html"),
        name="api_tos",
    ),
    # path(
    #     "admin/",
    #     admin.site.urls,
    # ),
]

if DEBUG:
    urlpatterns += [path("django-rq/", include("django_rq.urls"))]

if DEBUG_TOOLBAR:
    urlpatterns += [
        path(
            "__debug__/",
            include("debug_toolbar.urls"),
        ),
    ]
