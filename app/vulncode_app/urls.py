from django.conf.urls import url

from . import views

urlpatterns = [

    url(r'(?P<name>[a-z]+)/(?P<version>[0-9]+)', views.package_version, name="package_version"),
    url(r'^(?P<name>[a-z]+)', views.package, name="package"),
]
