import difflib
import json
import os.path

import requests
from django.contrib.auth import login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User
from django.contrib.auth.views import LoginView
from django.core.paginator import Paginator
from django.http import Http404
from django.http import HttpResponse
from django.http import HttpResponseBadRequest
from django.http import HttpResponseForbidden
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.shortcuts import redirect
from django.shortcuts import render
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.views.generic import CreateView
from django.views.generic import DetailView
from django.views.generic import FormView
from django.views.generic import ListView
from django.views.generic import TemplateView
from django.views.generic.edit import FormMixin

from purl_sync.settings import AP_CONTENT_TYPE
from purl_sync.settings import GIT_PATH
from purl_sync.settings import PURL_SYNC_DOMAIN
from purl_sync.settings import env
from review.forms import FetchForm
from review.forms import PersonSignUpForm
from review.forms import SearchPurlForm
from review.forms import SearchRepositoryForm
from review.forms import SearchReviewForm
from review.forms import SubscribePurlForm

from .activitypub import AP_CONTEXT
from .activitypub import AP_TARGET
from .activitypub import create_activity_obj
from .activitypub import has_valid_header
from .forms import CreateGitRepoForm
from .forms import CreateNoteForm
from .forms import CreateReviewForm
from .forms import ReviewStatusForm
from .models import Follow
from .models import Note
from .models import Person
from .models import Purl
from .models import Repository
from .models import Reputation
from .models import Review
from .models import Service
from .models import Vulnerability
from .signatures import PURL_SYNC_PRIVATE_KEY
from .signatures import HttpSignature
from .signatures import VerificationFormatError
from .utils import ap_collection
from .utils import clone_git_repo
from .utils import fetch_actor
from .utils import file_data
from .utils import full_reverse
from .utils import generate_webfinger
from .utils import load_git_file
from .utils import parse_webfinger
from .utils import webfinger_actor

PURL_SYNC_CLIENT_ID = env.str("PURL_SYNC_CLIENT_ID")
PURL_SYNC_CLIENT_SECRET = env.str("PURL_SYNC_CLIENT_SECRET")


class WebfingerView(View):
    def get(self, request):
        """/.well-known/webfinger?resource=acct:gargron@mastodon.social"""
        resource = request.GET.get("resource")

        if not resource:
            return HttpResponseBadRequest("No resource found")

        obj, domain = parse_webfinger(resource)

        if PURL_SYNC_DOMAIN != domain or not obj:
            return HttpResponseBadRequest("Invalid domain")

        if obj.startswith("pkg:"):
            try:
                purl = Purl.objects.get(string=obj)
            except Purl.DoesNotExist:
                return HttpResponseBadRequest("Not an Purl resource")

            return render(
                request,
                "webfinger_purl.json",
                status=200,
                content_type="application/jrd+json",
                context={
                    "resource": resource,
                    "domain": PURL_SYNC_DOMAIN,
                    "purl_string": purl.string,
                },
            )
        else:
            try:
                user = User.objects.get(username=obj)
            except User.DoesNotExist:
                return HttpResponseBadRequest("Not an account resource")

            return render(
                request,
                "webfinger_user.json",
                status=200,
                content_type="application/jrd+json",
                context={
                    "resource": resource,
                    "domain": PURL_SYNC_DOMAIN,
                    "username": user.username,
                },
            )


class HomeView(View):
    def get(self, request, *args, **kwargs):
        if hasattr(self.request.user, "person"):
            purls = [
                generate_webfinger(follow.purl.string)
                for follow in Follow.objects.filter(person=self.request.user.person)
            ]
            note_list = Note.objects.filter(acct__in=purls).order_by("updated_at__minute")
            paginator = Paginator(note_list, 10)
            page_number = request.GET.get("page")
            page_note = paginator.get_page(page_number)
            return render(request, "home.html", context={"notes": page_note})
        elif hasattr(self.request.user, "service"):
            return redirect("repo-list")
        else:
            return HttpResponseBadRequest("Invalid User Type")


class PersonView(DetailView):
    model = Person
    template_name = "user_profile.html"
    slug_field = "user__username"
    context_object_name = "person"

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(**kwargs)
        following_list = Follow.objects.filter(person=self.object)
        paginator = Paginator(following_list, 10)
        page_number = self.request.GET.get("page")
        context["followings"] = paginator.get_page(page_number)
        context["follow_count"] = following_list.count()
        return context


class PurlView(DetailView, FormMixin):
    model = Purl
    template_name = "purl_profile.html"
    slug_field = "string"
    context_object_name = "purl"
    form_class = CreateNoteForm

    def get_success_url(self):
        return self.request.path

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # slug = purl_string

        context["purl_notes"] = Note.objects.filter(acct=generate_webfinger(self.kwargs["slug"]))

        context["followers"] = Follow.objects.filter(purl=self.object)

        if self.request.user.is_authenticated:
            context["is_user_follow"] = (
                True
                if Follow.objects.filter(purl=self.object, person__user=self.request.user).first()
                else False
            )

        context["note_form"] = CreateNoteForm()
        context["subscribe_form"] = SubscribePurlForm()
        return context

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        note_form = self.get_form()
        if note_form.is_valid():
            note_form.instance.acct = generate_webfinger(self.kwargs["slug"])
            note_form.instance.note_type = 0
            note_form.save()
            return super(PurlView, self).form_valid(note_form)
        else:
            return self.form_invalid(note_form)


def is_service_user(view):
    def wrapper(request, *args, **kwargs):
        if hasattr(request.user, "service"):
            return view(request, *args, **kwargs)
        else:
            return HttpResponseForbidden()

    return wrapper


@method_decorator(is_service_user, name="dispatch")
class CreatGitView(LoginRequiredMixin, CreateView):
    model = Repository
    form_class = CreateGitRepoForm
    template_name = "create_repository.html"
    success_url = reverse_lazy("repo-list")

    def form_valid(self, form):
        self.object = form.save(commit=False)
        self.object.admin = self.request.user.service
        self.object.path = os.path.join(GIT_PATH, form.cleaned_data["name"])
        self.object.save()
        return super(CreatGitView, self).form_valid(form)


class UserLogin(LoginView):
    template_name = "login.html"
    next_page = "/review-list"


class PersonSignUp(FormView):
    form_class = PersonSignUpForm
    success_url = "/review-list"
    template_name = "user_sign_up.html"

    def form_valid(self, form):
        user = form.save()
        if user:
            person = Person.objects.create(user=user)
            person.save()
            login(self.request, user, backend="django.contrib.auth.backends.ModelBackend")
        return super(PersonSignUp, self).form_valid(form)


class RepositoryListView(ListView, FormMixin):
    model = Repository
    context_object_name = "repo_list"
    template_name = "repo_list.html"
    paginate_by = 10
    form_class = SearchRepositoryForm

    def get_queryset(self):
        form = self.form_class(self.request.GET)
        if form.is_valid():
            return Repository.objects.filter(url__icontains=form.cleaned_data.get("search"))
        return Repository.objects.all()


class ReviewListView(ListView, FormMixin):
    model = Review
    context_object_name = "review_list"
    template_name = "review_list.html"
    paginate_by = 10
    form_class = SearchReviewForm

    def get_queryset(self):
        form = self.form_class(self.request.GET)
        if form.is_valid():
            return Review.objects.filter(headline__icontains=form.cleaned_data.get("search"))
        return Review.objects.all()


class PurlListView(ListView, FormMixin):
    model = Purl
    context_object_name = "purl_list"
    template_name = "purl_list.html"
    paginate_by = 20
    form_class = SearchPurlForm

    def get_queryset(self):
        form = self.form_class(self.request.GET)
        if form.is_valid():
            return Purl.objects.filter(string__icontains=form.cleaned_data.get("search"))
        return Purl.objects.all()


class ReviewView(LoginRequiredMixin, TemplateView):
    template_name = "review.html"

    def get_context_data(self, request, **kwargs):
        context = super().get_context_data(**kwargs)
        context["review"] = get_object_or_404(Review, id=self.kwargs["review_id"])
        vul_source = context["review"].data.splitlines()
        vul_target = load_git_file(
            git_repo_obj=context["review"].vulnerability.repo.git_repo_obj,
            filename=context["review"].vulnerability.filename,
            commit_id=context["review"].commit_id,
        ).splitlines()
        d = difflib.HtmlDiff()
        context["patch"] = d.make_table(
            vul_source, vul_target, fromdesc="original", todesc="modified"
        )
        return context

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(request, **kwargs)
        return render(
            request,
            self.template_name,
            {"status_form": ReviewStatusForm(), "comment_form": CreateNoteForm(), **context},
        )

    def post(self, request, *args, **kwargs):
        context = self.get_context_data(request, **kwargs)
        status_form = ReviewStatusForm(request.POST, instance=context["review"])
        comment_form = CreateNoteForm(request.POST)
        if status_form.is_bound and status_form.is_valid():
            status_form.save()

        elif comment_form.is_bound and comment_form.is_valid():
            comment_form.save(commit=False)
            comment_form.instance.acct = generate_webfinger(request.user.username)
            comment = comment_form.save()
            context["review"].notes.add(comment)
            context["review"].save()

        status_form = ReviewStatusForm()
        comment_form = CreateNoteForm()
        context = self.get_context_data(request, **kwargs)
        return render(
            request,
            self.template_name,
            {"status_form": status_form, "comment_form": comment_form, **context},
        )


def fetch_repository_file(request, repository_id):
    if request.headers.get("x-requested-with") == "XMLHttpRequest" and request.method == "POST":
        request_body = json.load(request)
        path = request_body.get("path")

        repo = get_object_or_404(Repository, id=repository_id).git_repo_obj
        for entry in repo.commit().tree.traverse():
            if path == entry.path:
                with open(entry.abspath) as f:
                    return JsonResponse({"filename": path, "text": f.read()})
    return HttpResponseBadRequest("Can't fetch this file")


# TODO remove duplication vote in views
def review_vote(request, review_id):
    if request.headers.get("x-requested-with") == "XMLHttpRequest" and request.method == "PUT":
        user_webfinger = generate_webfinger(request.user.username)
        review = Review.objects.get(id=review_id)
        acceptor = review.author
        request_body = json.load(request)
        if request_body.get("vote-type") == "vote-up-review":
            rep_obj, created = Reputation.objects.get_or_create(
                voter=user_webfinger,
                acceptor=acceptor.acct,
                positive=True,
            )
        elif request_body.get("vote-type") == "vote-down-review":
            rep_obj, created = Reputation.objects.get_or_create(
                voter=user_webfinger,
                acceptor=acceptor.acct,
                positive=False,
            )
        else:
            return HttpResponseBadRequest("Invalid review-vote request")

        if not created:
            review.reputation.remove(rep_obj)
            rep_obj.delete()
            return JsonResponse(
                {
                    "message": "The vote has been removed successfully",
                    "vote-type": rep_obj.positive,
                    "deleted": True,
                }
            )
        else:
            review.reputation.add(rep_obj)
            return JsonResponse(
                {
                    "message": "Voting completed successfully",
                    "vote-type": rep_obj.positive,
                    "deleted": False,
                }
            )

    return JsonResponse(request, {"message": "successfully voted"})


def note_vote(request, note_id):
    if request.headers.get("x-requested-with") == "XMLHttpRequest" and request.method == "PUT":
        user_webfinger = generate_webfinger(request.user.username)
        note = Note.objects.get(id=note_id)
        request_body = json.load(request)
        if request_body.get("vote-type") == "vote-up-note":
            rep_obj, created = Reputation.objects.get_or_create(
                voter=user_webfinger,
                acceptor=note.acct,
                positive=True,
            )

        elif request_body.get("vote-type") == "vote-down-note":
            rep_obj, created = Reputation.objects.get_or_create(
                voter=user_webfinger,
                acceptor=note.acct,
                positive=False,
            )

        else:
            return HttpResponseBadRequest("Invalid note-vote request")

        if not created:
            note.reputation.remove(rep_obj)
            rep_obj.delete()
            return JsonResponse(
                {
                    "message": "The vote has been removed successfully",
                    "vote-type": rep_obj.positive,
                    "deleted": True,
                }
            )
        else:
            note.reputation.add(rep_obj)
            return JsonResponse(
                {
                    "message": "Voting completed successfully",
                    "vote-type": rep_obj.positive,
                    "deleted": False,
                }
            )


class FollowPurlView(View):
    def post(self, request, *args, **kwargs):
        purl = Purl.objects.get(string=self.kwargs["purl_string"])
        if request.user.is_authenticated:
            if "follow" in request.POST:
                follow_obj, _ = Follow.objects.get_or_create(
                    person=self.request.user.person, purl=purl
                )

            elif "unfollow" in request.POST:
                try:
                    follow_obj = Follow.objects.get(person=self.request.user.person, purl=purl)
                    follow_obj.delete()
                except Follow.DoesNotExist:
                    return HttpResponseBadRequest(
                        "Some thing went wrong when you try to unfollow this purl"
                    )
        elif request.user.is_anonymous:
            form = SubscribePurlForm(request.POST)
            if form.is_valid():
                user, domain = parse_webfinger(form.cleaned_data.get("acct"))
                remote_actor_url = webfinger_actor(user, domain)

                payload = json.dumps(
                    {
                        **AP_CONTEXT,
                        "type": "Follow",
                        "actor": {
                            "type": "Person",
                            "id": remote_actor_url,
                        },
                        "object": {
                            "type": "Purl",
                            "id": purl.absolute_url_ap,
                        },
                        "to": [remote_actor_url],
                    }
                )

                activity = create_activity_obj(payload)
                activity_response = activity.handler()
                return JsonResponse(
                    {
                        "redirect_url": f"https://{domain}/authorize_interaction?uri={remote_actor_url}"
                    }
                )
            else:
                return HttpResponseBadRequest()

        return redirect(".")


class CreateReview(LoginRequiredMixin, TemplateView):
    template_name = "create_review.html"

    def get_context_data(self, request, **kwargs):
        context = super().get_context_data(**kwargs)
        repo = Repository.objects.get(id=self.kwargs["repository_id"])
        context["git_files_tree"] = [
            entry.path
            for entry in repo.git_repo_obj.commit().tree.traverse()
            if entry.type == "blob"
        ]
        return context

    def get(self, request, *args, **kwargs):
        context = self.get_context_data(request, **kwargs)
        return render(
            request,
            self.template_name,
            {**context, "create_review_form": CreateReviewForm(), "fetch_form": FetchForm()},
        )

    def post(self, request, *args, **kwargs):
        create_review_form = CreateReviewForm(request.POST)
        if create_review_form.is_valid() and request.user.person:
            repo = Repository.objects.get(id=self.kwargs["repository_id"])
            commit = repo.git_repo_obj.head.commit
            vuln, _ = Vulnerability.objects.get_or_create(
                repo=repo,
                filename=create_review_form.cleaned_data["filename"],
            )

            review = Review.objects.create(
                headline=create_review_form.cleaned_data["headline"],
                data=create_review_form.cleaned_data["data"],
                author=request.user.person,
                vulnerability=vuln,
                commit_id=commit,
            )
            review.save()
        context = self.get_context_data(request, **kwargs)
        return render(
            request,
            self.template_name,
            {**context, "create_review_form": CreateReviewForm(), "fetch_form": FetchForm()},
        )


class NoteView(LoginRequiredMixin, FormMixin, DetailView):
    template_name = "note.html"
    model = Note
    context_object_name = "note"
    slug_field = "id"
    slug_url_kwarg = "uuid"
    form_class = CreateNoteForm

    def get_context_data(self, **kwargs):
        context = super(NoteView, self).get_context_data(**kwargs)
        context["form"] = CreateNoteForm()
        return context

    def post(self, request, *args, **kwargs):
        """Create a note"""
        comment_form = self.get_form()
        if comment_form.is_valid():
            comment_form.instance.acct = generate_webfinger(request.user.username)
            comment_form.instance.reply_to = Note.objects.get(id=self.kwargs["uuid"])
            comment_form.save()
            return self.get(request)
        else:
            return self.form_invalid(comment_form)


@method_decorator(has_valid_header, name="dispatch")
class UserProfile(View):
    def get(self, request, *args, **kwargs):
        """"""
        try:
            user = User.objects.get(username=kwargs["username"])
        except User.DoesNotExist:
            return HttpResponseBadRequest("User doesn't exist")

        if request.GET.get("main-key"):
            return HttpResponse(
                user.person.public_key if hasattr(user, "person") else user.service.public_key
            )

        if hasattr(user, "person"):
            return JsonResponse(user.person.to_ap, content_type=AP_CONTENT_TYPE)
        elif hasattr(user, "service"):
            return JsonResponse(user.service.to_ap, content_type=AP_CONTENT_TYPE)
        else:
            return HttpResponseBadRequest("Invalid type user")


@method_decorator(has_valid_header, name="dispatch")
class PurlProfile(View):
    def get(self, request, *args, **kwargs):
        """"""
        try:
            purl = Purl.objects.get(string=kwargs["purl_string"])
        except Purl.DoesNotExist:
            return HttpResponseBadRequest("Invalid type user")

        if request.GET.get("main-key"):
            return HttpResponse(purl.public_key)

        return JsonResponse(purl.to_ap, content_type=AP_CONTENT_TYPE)


@method_decorator(has_valid_header, name="dispatch")
class UserInbox(View):
    def get(self, request, *args, **kwargs):
        """You can GET from your inbox to read your latest messages
        (client-to-server; this is like reading your social network stream)"""
        if hasattr(request.user, "person") and request.user.username == kwargs["username"]:
            purl_followers = [
                generate_webfinger(follow.purl.string)
                for follow in Follow.objects.filter(person=request.user.person)
            ]
            note_list = Note.objects.filter(acct__in=purl_followers).order_by("updated_at__minute")
            reviews = Review.objects.filter(author=request.user.person)
            return JsonResponse(
                {"notes": ap_collection(note_list), "reviews": ap_collection(reviews)},
                content_type=AP_CONTENT_TYPE,
            )

    def post(self, request, *args, **kwargs):
        """You can POST to someone's inbox to send them a message
        (server-to-server / federation only... this is federation!)"""
        return NotImplementedError


@method_decorator(has_valid_header, name="dispatch")
class UserOutbox(View):
    def get(self, request, *args, **kwargs):
        """You can GET from someone's outbox to see what messages they've posted
        (or at least the ones you're authorized to see).
        (client-to-server and/or server-to-server)"""
        try:
            user = User.objects.get(username=kwargs["username"])
        except User.DoesNotExist:
            user = None

        if hasattr(user, "person"):
            notes = Note.objects.filter(acct=user.person.acct)
            reviews = Review.objects.filter(author=user.person)
            return JsonResponse(
                {
                    "notes": ap_collection(notes),
                    "reviews": ap_collection(reviews),
                },
                content_type=AP_CONTENT_TYPE,
            )
        elif hasattr(user, "service"):
            repos = Repository.objects.filter(admin=user.service)
            return JsonResponse(
                {
                    "repositories": ap_collection(repos),
                },
                content_type=AP_CONTENT_TYPE,
            )
        else:
            return HttpResponseBadRequest("Can't find this user")

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        """You can POST to your outbox to send messages to the world (client-to-server)"""
        if request.user.is_authenticated and request.user.username == kwargs["username"]:
            activity = create_activity_obj(request.body)
            if activity:
                return activity.handler()

        return HttpResponseBadRequest("Invalid message")


@method_decorator(has_valid_header, name="dispatch")
class PurlInbox(View):
    def get(self, request, *args, **kwargs):
        """
        You can GET from your inbox to read your latest messages
        (client-to-server; this is like reading your social network stream)
        """
        try:
            purl = Purl.objects.get(string=kwargs["purl_string"])
        except Purl.DoesNotExist:
            purl = None

        if hasattr(request.user, "service") and purl:
            return JsonResponse(
                {
                    "notes": ap_collection(purl.notes.all()),
                },
                content_type="application/activity+json",
            )
        return HttpResponseBadRequest()

    @csrf_exempt
    def post(self, request, *args, **kwargs):
        """
        You can POST to someone's inbox to send them a message
        (server-to-server / federation only... this is federation!)
        """
        return NotImplementedError


@method_decorator(has_valid_header, name="dispatch")
class PurlOutbox(View):
    def get(self, request, *args, **kwargs):
        """GET from someone's outbox to see what messages they've posted
        (or at least the ones you're authorized to see).
        (client-to-server and/or server-to-server)"""

        actor = Purl.objects.get(string=kwargs["purl_string"])
        return JsonResponse(
            {"notes": ap_collection(actor.notes)},
            content_type=AP_CONTENT_TYPE,
        )

    def post(self, request, *args, **kwargs):
        """You can POST to your outbox to send messages to the world (client-to-server)"""
        try:
            actor = Purl.objects.get(string=kwargs["purl_string"])
        except Purl.DoesNotExist:
            return HttpResponseBadRequest("Invalid purl")

        if (
            request.user.is_authenticated
            and hasattr(request.user, "service")
            and actor.service == request.user.service
        ):
            activity = create_activity_obj(request.body)
            return activity.handler()
        return HttpResponseBadRequest("Invalid Message")


def redirect_repository(request, repository_id):
    try:
        repo = Repository.objects.get(id=repository_id)
    except Repository.DoesNotExist:
        raise Http404("Repository does not exist")
    return redirect(repo.url)


def redirect_vulnerability(request, vulnerability_id):
    try:
        vulnerability = Vulnerability.objects.get(id=vulnerability_id)
    except Vulnerability.DoesNotExist:
        raise Http404("Vulnerability does not exist")
    return HttpResponse(vulnerability.load_file)


class UserFollowing(View):
    def get(self, request, *args, **kwargs):
        followings = Follow.objects.filter(person__user__username=self.kwargs["username"])
        return JsonResponse(
            [full_reverse(following) for following in followings],
            content_type="application/activity+json",
        )


class PurlFollowers(View):
    def get(self, request, *args, **kwargs):
        followers = Follow.objects.filter(purl__string=self.kwargs["purl_string"])
        return JsonResponse(
            [full_reverse(following) for following in followers],
            content_type=AP_CONTENT_TYPE,
        )


@require_http_methods(["POST"])
@csrf_exempt
def token(request):
    payload = json.loads(request.body)
    r = requests.post(
        "http://127.0.0.1:8000/o/token/",
        headers={"content-type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "password",
            "username": payload["username"],
            "password": payload["password"],
            "client_id": PURL_SYNC_CLIENT_ID,
            "client_secret": PURL_SYNC_CLIENT_SECRET,
        },
    )
    return JsonResponse(json.loads(r.content), status=r.status_code, content_type=AP_CONTENT_TYPE)


@require_http_methods(["POST"])
@csrf_exempt
def refresh_token(request):
    payload = json.loads(request.body)
    r = requests.post(
        "http://127.0.0.1:8000/o/token/",
        headers={"content-type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "refresh_token",
            "refresh_token": payload["refresh_token"],
            "client_id": PURL_SYNC_CLIENT_ID,
            "client_secret": PURL_SYNC_CLIENT_SECRET,
        },
    )
    return JsonResponse(json.loads(r.text), status=r.status_code, content_type=AP_CONTENT_TYPE)


@require_http_methods(["POST"])
@csrf_exempt
def revoke_token(request):
    payload = json.loads(request.body)
    r = requests.post(
        "http://127.0.0.1:8000/o/revoke_token/",
        headers={"content-type": "application/x-www-form-urlencoded"},
        data={
            "token": payload["token"],
            "client_id": PURL_SYNC_CLIENT_ID,
            "client_secret": PURL_SYNC_CLIENT_SECRET,
        },
    )
    return JsonResponse(json.loads(r.content), status=r.status_code, content_type=AP_CONTENT_TYPE)
