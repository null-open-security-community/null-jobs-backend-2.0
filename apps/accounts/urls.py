from django.urls import include, path
from rest_framework import routers

from . import views

app_name = "apps.accounts"

# router = routers.DefaultRouter()
# router.register("", views.SampleViewSet, basename="sample")

# # Additionally, we include login URLs for the browsable API.
# urlpatterns = [
#     path('accounts/', include(router.urls))
# ]


from django.urls import include, path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

from apps.accounts.views import *

# Accounts App Public APIs
public_apis_accounts = [
    "/register/",
    "/login/",
    "/google/login/",
    "/google/login/callback/",
    "/forget-password/",
    "/forget-password/verify/",
    "/token/refresh/",
    "/token/verify/",
    "/otp/verify/",
    "/restricted/",
]

urlpatterns = [
    # Generate Access Token using Refresh Token
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("token/verify/", TokenVerifyView.as_view(), name="token_verify"),
    path("register/", UserRegistrationView.as_view(), name="register"),
    path("otp/verify/", OTPVerificationCheckView.as_view(), name="verify_otp"),
    path("login/", UserLoginView.as_view(), name="login"),
    path("profile/", UserProfileView.as_view(), name="profile"),
    path("logout/", UserLogOutView.as_view(), name="logout"),
    path("restricted/", RestrictedPage.as_view(), name="restricted"),
    path(
        "forget-password/",
        SendPasswordResetOTPView.as_view(),
        name="send-reset-password-otp",
    ),
    path(
        "forget-password/verify/",
        ResetPasswordOtpVerifyView.as_view(),
        name="verify-reset-password-otp",
    ),
    path(
        "reset-password/",
        UserPasswordResetView.as_view(),
        name="reset-password",
    ),
    path("changepassword/", UserChangePasswordView.as_view(), name="changepassword"),
    path(
        "changepassword/otp/verify/",
        UserChangePasswordOTPView.as_view(),
        name="changepassword_otp_verify",
    ),
    # this comes in play when we want token from the code provided by callback. hit this url and send code in body it will return the
    # path('auth/google/', GoogleLogin.as_view(), name='google_login'),
    # needed for google auth
    path("google/login/", GoogleHandle.as_view(), name="google"),
    path("google/login/callback/", CallbackHandleView.as_view(), name="callback"),
    # path("google/additional-details/", AdditionalUserInfoView.as_view(), name='additonal'),
]
