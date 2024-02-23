from django.urls import include, path
from rest_framework import routers

from apps.jobs.views import (
    CompanyViewSets,
    ContactUsViewSet,
    JobViewSets,
    ModeratorViewSet,
    UserViewSets,
)

# app name for namespace
app_name = "apps.jobs"

# Jobs App Public APIs
public_apis_jobs = [
    "/contact-us/create_contact_message/",
    "/jobs/public_jobs/",
    "/jobs/get_jobs_categories/",
    "/jobs/get_jobs/",
    "/jobs/featured_jobs/",
    "/jobs/get_posted_jobs/",
    "/jobs/get_trending_keywords/"
]

# create a router
router = routers.DefaultRouter()
router.register(r"jobs", JobViewSets)
router.register(r"user", UserViewSets)
router.register(r"company", CompanyViewSets)
router.register(r"contact-us", ContactUsViewSet, basename="contact-us")

urlpatterns = [path("", include(router.urls), name="Default")]
