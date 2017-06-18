from django.conf.urls import url

from . import views

urlpatterns = [

    url(r'(?P<product>[a-z]+)/(?P<ver>[0-9]+)', views.product_ver, name="product_ver"),
    url(r'^(?P<product>[a-z]+)', views.product, name="product"),
]