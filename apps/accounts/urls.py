from django.urls import include, path
from rest_framework import routers

from . import views

app_name = "accounts"

router = routers.DefaultRouter()
router.register("", views.SampleViewSet, basename="sample")

# Wire up our API using automatic URL routing.
# Additionally, we include login URLs for the browsable API.
urlpatterns = [
    path('accounts/', include(router.urls))
]