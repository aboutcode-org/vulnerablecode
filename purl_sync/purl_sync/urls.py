#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/nexB/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth.views import LogoutView
from django.urls import include
from django.urls import path

from review import views
from review.views import CreateReview
from review.views import CreatGitView
from review.views import FollowPurlView
from review.views import HomeView
from review.views import NoteView
from review.views import PersonSignUp
from review.views import PersonView
from review.views import PurlFollowers
from review.views import PurlInbox
from review.views import PurlListView
from review.views import PurlOutbox
from review.views import PurlProfile
from review.views import PurlView
from review.views import RepositoryListView
from review.views import ReviewListView
from review.views import ReviewView
from review.views import UserFollowing
from review.views import UserInbox
from review.views import UserLogin
from review.views import UserOutbox
from review.views import UserProfile
from review.views import WebfingerView
from review.views import fetch_repository_file
from review.views import note_vote
from review.views import redirect_repository
from review.views import redirect_vulnerability
from review.views import review_vote

urlpatterns = [
    path("admin/", admin.site.urls),
    path(".well-known/webfinger", WebfingerView.as_view(), name="web-finger"),
    path("", HomeView.as_view(), name="home-page"),
    path("users/@<str:slug>", PersonView.as_view(), name="user-profile"),
    path("purls/@<path:slug>/", PurlView.as_view(), name="purl-profile"),
    path("purls/@<path:purl_string>/follow", FollowPurlView.as_view(), name="purl-follow"),
    path("accounts/sign-up", PersonSignUp.as_view(), name="signup"),
    path("accounts/login/", UserLogin.as_view(), name="login"),
    path("accounts/logout", LogoutView.as_view(next_page="login"), name="logout"),
    path("create-repo", CreatGitView.as_view(), name="repo-create"),
    path("repo-list", RepositoryListView.as_view(), name="repo-list"),
    path("purl-list", PurlListView.as_view(), name="purl-list"),
    path(
        "repository/<uuid:repository_id>/create-review/",
        CreateReview.as_view(),
        name="review-create",
    ),
    path("review-list", ReviewListView.as_view(), name="review-list"),
    path("reviews/<uuid:review_id>/", ReviewView.as_view(), name="review-page"),
    path("reviews/<uuid:review_id>/votes/", review_vote, name="review-votes"),
    path("notes/<uuid:note_id>/votes/", note_vote, name="comment-votes"),
    path("repository/<uuid:repository_id>/", redirect_repository, name="repository-page"),
    path("repository/<uuid:repository_id>/fetch", fetch_repository_file, name="repository-fetch"),
    path(
        "vulnerability/<uuid:vulnerability_id>/", redirect_vulnerability, name="vulnerability-page"
    ),
    path("notes/<uuid:uuid>", NoteView.as_view(), name="note-page"),
    path("api/v0/users/@<str:username>", UserProfile.as_view(), name="user-ap-profile"),
    path("api/v0/purls/@<path:purl_string>/", PurlProfile.as_view(), name="purl-ap-profile"),
    path("api/v0/users/@<str:username>/inbox", UserInbox.as_view(), name="user-inbox"),
    path("api/v0/users/@<str:username>/outbox", UserOutbox.as_view(), name="user-outbox"),
    path("api/v0/purls/@<path:purl_string>/inbox", PurlInbox.as_view(), name="purl-inbox"),
    path("api/v0/purls/@<path:purl_string>/outbox", PurlOutbox.as_view(), name="purl-outbox"),
    path("api/v0/users/@<str:username>/following/", UserFollowing.as_view(), name="user-following"),
    path(
        "api/v0/purls/@<path:purl_string>/followers/",
        PurlFollowers.as_view(),
        name="purl-followers",
    ),
    path("auth/token/", views.token),
    path("auth/refresh_token/", views.refresh_token),
    path("auth/revoke_token/", views.revoke_token),
    path("o/", include("oauth2_provider.urls", namespace="oauth2_provider")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
