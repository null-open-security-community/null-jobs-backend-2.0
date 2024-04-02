from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.userprofile.views import UserProfileViewSet, UplaodDocumentsView

app_name = "apps.userprofile"

router = DefaultRouter()
router.register(r"user", UserProfileViewSet)

urlpatterns = [
    path("", include(router.urls), name="userprofile"),
    path("uploaddocuments", UplaodDocumentsView.as_view(), name="uploaddocuments")
]
