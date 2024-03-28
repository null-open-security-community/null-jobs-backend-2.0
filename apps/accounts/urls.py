from django.urls import path

from apps.accounts.views import (
    UserRegistrationView,
    OTPVerificationCheckView,
    UserLoginView,
    UserProfileView,
    UserLogOutView,
    SendPasswordResetOTPView,
    ResetPasswordOtpVerifyView,
    UserPasswordResetView,
    UserChangePasswordOTPView,
    UserChangePasswordView,
    GoogleHandle, CallbackHandleView
)

app_name = "apps.accounts"

from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView



urlpatterns = [
    # Generate Access Token using Refresh Token
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("token/verify/", TokenVerifyView.as_view(), name="token_verify"),
    path("register/", UserRegistrationView.as_view(), name="register"),
    path("otp/verify/", OTPVerificationCheckView.as_view(), name="verify_otp"),
    path("login/", UserLoginView.as_view(), name="login"),
    path("profile/", UserProfileView.as_view(), name="profile"),
    path("logout/", UserLogOutView.as_view(), name="logout"),
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

    # google oauth endpoints
    path("google/login/", GoogleHandle.as_view(), name="google"),
    path("google/login/callback/", CallbackHandleView.as_view(), name="callback")
]
