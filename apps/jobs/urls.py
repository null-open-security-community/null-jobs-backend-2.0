from rest_framework import routers
from django.urls import path, include
from .views import JobViewSets, UserViewSets, CompanyViewSets

# app name for namespace
app_name = "jobs"

# create a router
router = routers.DefaultRouter()
router.register(r"jobs", JobViewSets)
router.register(r"user", UserViewSets)
router.register(r"company", CompanyViewSets)

urlpatterns = [path("", include(router.urls), name="Default")]
