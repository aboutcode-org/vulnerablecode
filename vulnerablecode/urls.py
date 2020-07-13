#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/vulnerablecode/
# The VulnerableCode software is licensed under the Apache License version 2.0.
# Data generated with VulnerableCode require an acknowledgment.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with VulnerableCode or any VulnerableCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with VulnerableCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  VulnerableCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  VulnerableCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/vulnerablecode/ for support and download.

from django.contrib import admin
from django.urls import include, path, re_path

from rest_framework.routers import DefaultRouter

from vulnerabilities.api import PackageViewSet
from vulnerabilities.views import PackageSearchView
from vulnerabilities.views import PackageUpdate
from vulnerabilities.views import PackageCreate
from vulnerabilities.views import VulnerabilityDetails
from vulnerabilities.views import VulnerabilitySearchView
from vulnerabilities.views import VulnerabilityCreate
from vulnerabilities.views import ResolvedPackageDelete
from vulnerabilities.views import ImpactedPackageDelete
from vulnerabilities.views import ImpactedPackageCreate
from vulnerabilities.views import ResolvedPackageCreate
from vulnerabilities.views import HomePage
from vulnerabilities.views import VulnerabilityReferenceCreate


api_router = DefaultRouter()
api_router.register(r'packages', PackageViewSet)


urlpatterns = [
    path('admin/', admin.site.urls),
    re_path(r'^api/', include(api_router.urls)),
    path('packages/search', PackageSearchView.as_view(), name="package_search"),
    path('packages/<int:pk>', PackageUpdate.as_view(), name="package_view"),
    path('vulnerabilities/<int:pk>', VulnerabilityDetails.as_view(), name="vulnerability_view"),
    path('vulnerabilities/search', VulnerabilitySearchView.as_view(), name="vulnerability_search"),
    path('vulnerabilities/create', VulnerabilityCreate.as_view(), name="vulnerability_create"),
    path('packages/create', PackageCreate.as_view(), name="package_create"),
    path('relations/resolved/<int:pid>/<int:vid>', ResolvedPackageDelete.as_view(), name="resolved_package_delete"),
    path('relations/impacted/<int:pid>/<int:vid>', ImpactedPackageDelete.as_view(), name="impacted_package_delete"),
    path('relations/impacted/<int:pid>/create', ImpactedPackageCreate.as_view(), name="impacted_package_create"),
    path('relations/resolved/<int:pid>/create', ResolvedPackageCreate.as_view(), name="resolved_package_create"),
    path('relations/reference/<int:vid>/create', VulnerabilityReferenceCreate.as_view(), name="vulnerability_reference_create"),
    path('', HomePage.as_view(), name="home")
]
