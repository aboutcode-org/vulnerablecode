from django.urls import path

from agent.views import VulnAgent

urlpatterns = [
    path(
        "",
        VulnAgent.as_view(),
        name="vuln-agent",
    ),
]
