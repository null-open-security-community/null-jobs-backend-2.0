from django.urls import include, path
from rest_framework import routers

from apps.jobs.views import (
    CompanyViewSets, ContactUsViewSet, 
    JobViewSets, CompanyStats
)

# app name for namespace
app_name = "apps.jobs"

# create a router
router = routers.DefaultRouter()
router.register(r"jobs", JobViewSets)
router.register(r"company", CompanyViewSets)
router.register(r"contact-us", ContactUsViewSet, basename="contact-us")

urlpatterns = [
    path("", include(router.urls), name="Default"),
    path(
        "company/stats",
        CompanyStats.as_view(),
        name="companystats"
    )
]
