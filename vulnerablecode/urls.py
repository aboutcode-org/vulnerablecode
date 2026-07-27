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

from vulnerabilities.api_v3 import AdvisoryV3ViewSet
from vulnerabilities.api_v3 import AffectedByAdvisoriesViewSet
from vulnerabilities.api_v3 import FixingAdvisoriesViewSet
from vulnerabilities.api_v3 import PackageTypesView
from vulnerabilities.api_v3 import PackageV3ViewSet
from vulnerabilities.views import AdminLoginView
from vulnerabilities.views import AdvisoryDetails
from vulnerabilities.views import AdvisoryMitigationCurationView
from vulnerabilities.views import AdvisoryPackageCommitPatchDetails
from vulnerabilities.views import AdvisoryPackageCurationView
from vulnerabilities.views import AdvisoryPackagesDetails
from vulnerabilities.views import AdvisorySeverityCurationView
from vulnerabilities.views import AdvisoryToDoListView
from vulnerabilities.views import AdvisoryWeaknessCurationView
from vulnerabilities.views import AffectedByAdvisoriesListView
from vulnerabilities.views import AltchaView
from vulnerabilities.views import ApiUserCreateView
from vulnerabilities.views import FixingAdvisoriesListView
from vulnerabilities.views import HomePageV2
from vulnerabilities.views import PackageSearchV2
from vulnerabilities.views import PackageV2Details
from vulnerabilities.views import PipelineRunDetailView
from vulnerabilities.views import PipelineRunListView
from vulnerabilities.views import PipelineScheduleListView
from vulnerablecode.settings import ALTCHA_SESSION_TIMEOUT
from vulnerablecode.settings import DEBUG
from vulnerablecode.settings import DEBUG_TOOLBAR


# See the comment at https://stackoverflow.com/a/46163870.
class OptionalSlashRouter(DefaultRouter):
    def __init__(self, *args, **kwargs):
        super(DefaultRouter, self).__init__(*args, **kwargs)
        self.trailing_slash = "/?"


api_v3_router = OptionalSlashRouter()

api_v3_router.register("packages", PackageV3ViewSet, basename="package-v3")
api_v3_router.register("advisories", AdvisoryV3ViewSet, basename="advisory-v3")
api_v3_router.register(
    "affected-by-advisories", AffectedByAdvisoriesViewSet, basename="affected-by-advisories"
)
api_v3_router.register("fixing-advisories", FixingAdvisoriesViewSet, basename="fixing-advisories")
api_v3_router.register("package-types", PackageTypesView, basename="package-types")

urlpatterns = [
    path("admin/login/", AdminLoginView.as_view(), name="admin-login"),
    path("api/v3/", include(api_v3_router.urls)),
    path(
        "robots.txt",
        TemplateView.as_view(template_name="robots.txt", content_type="text/plain"),
    ),
    path(
        "",
        HomePageV2.as_view(),
        name="home",
    ),
    path(
        "pipelines/dashboard/",
        PipelineScheduleListView.as_view(),
        name="dashboard",
    ),
    path(
        "advisories/todos/",
        AdvisoryToDoListView.as_view(),
        name="todo-list",
    ),
    path(
        "advisories/todos/<uuid:todo_id>/package/curate/",
        AdvisoryPackageCurationView.as_view(),
        name="todo-detail",
    ),
    path(
        "advisories/todos/<uuid:todo_id>/severity/curate/",
        AdvisorySeverityCurationView.as_view(),
        name="todo-severity-detail",
    ),
    path(
        "advisories/todos/<uuid:todo_id>/weakness/curate/",
        AdvisoryWeaknessCurationView.as_view(),
        name="todo-weakness-detail",
    ),
    path(
        "advisories/todos/<uuid:todo_id>/mitigation/curate/",
        AdvisoryMitigationCurationView.as_view(),
        name="todo-mitigation-detail",
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
        "advisories/packages/<path:avid>",
        AdvisoryPackagesDetails.as_view(),
        name="advisory_package_details",
    ),
    path(
        "advisories/commits/<path:avid>",
        AdvisoryPackageCommitPatchDetails.as_view(),
        name="advisory_package_commit_details",
    ),
    path(
        "advisories/<path:avid>",
        AdvisoryDetails.as_view(),
        name="advisory_details",
    ),
    path(
        "packages/v2/search/",
        PackageSearchV2.as_view(),
        name="package_search_v2",
    ),
    re_path(
        r"^packages/v2/(?P<purl>pkg:.+)$",
        PackageV2Details.as_view(),
        name="package_details_v2",
    ),
    re_path(
        r"^fixing-advisories/v2/(?P<purl>pkg:.+)$",
        FixingAdvisoriesListView.as_view(),
        name="fixing_advisories_v2",
    ),
    re_path(
        r"^affected-by-advisories/v2/(?P<purl>pkg:.+)$",
        AffectedByAdvisoriesListView.as_view(),
        name="affected_by_advisories_v2",
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

if ALTCHA_SESSION_TIMEOUT:
    urlpatterns += [path("altcha/", AltchaView.as_view(), name="altcha")]

if DEBUG:
    urlpatterns += [path("django-rq/", include("django_rq.urls"))]

if DEBUG_TOOLBAR:
    urlpatterns += [
        path(
            "__debug__/",
            include("debug_toolbar.urls"),
        ),
    ]
