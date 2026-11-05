#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

from django.urls import path

from insights import views

urlpatterns = [
    path("", views.insights_dashboard, name="insights-dashboard"),
    path("<str:panel_id>/", views.insights_dashboard, name="insights-panel"),
]
