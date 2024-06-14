import datetime
import logging
import secrets

# from django.urls import reverse
import urllib.parse

import requests
from django.conf import settings
from django.contrib.auth import authenticate
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from apps.accounts.models import User
from apps.accounts.renderers import UserRenderer
from apps.accounts.serializers import (
    OTPVerificationCheckSerializer,
    SendPasswordResetOTPSerializer,
    UserChangePasswordOTPSerializer,
    UserChangePasswordSerializer,
    UserLoginResponseSerializer,
    UserLoginSerializer,
    UserPasswordResetSerializer,
    UserRegistrationResponseSerializer,
    UserRegistrationSerializer,
    UserSerializer,
)
from apps.accounts.utils import *
from apps.userprofile.models import UserProfile

# from django.shortcuts import render


# #google auth
# from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
# from allauth.socialaccount.providers.oauth2.client import OAuth2Client
# from dj_rest_auth.registration.views import SocialLoginView


logger = logging.getLogger(__name__)


# Generate token Manually
class TokenUtility:
    @staticmethod
    def get_tokens_for_user(user):
        refresh = RefreshToken.for_user(user)
        # custom_payload={"name":user.name,"email":user.email}
        # refresh.payload.update(custom_payload)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user_type": user.user_type
        }

    @staticmethod
    def generate_dummy_jwt_token(Cpayload):
        # creating custom payload with 5 minutes expiration time
        custom_payload = {
            "exp": datetime.datetime.utcnow()
            + settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"]
        }
        custom_payload.update(Cpayload)
        # Create a new AccessToken with the custom payload
        access_token = AccessToken()
        access_token.payload.update(custom_payload)
        return str(access_token)

    @staticmethod
    def add_payload(token, payload):
        access_token = AccessToken(token)
        access_token.payload.update(payload)
        return str(access_token)

    @staticmethod
    def verify_and_get_payload(token):
        try:
            # Decode the token and verify its validity
            access_token = AccessToken(token)
            # Getting payload
            payload = access_token.payload
            return payload
        except InvalidToken:
            # Token is invalid
            raise InvalidToken("Invalid token")
        except TokenError:
            # Some other token-related error
            raise TokenError("Token expired")


def generate_guest_token(user, purpose):
    payload = {
        "email": user.email,
        "user_id": str(user.id),
        "user_type": user.user_type,
    }
    token = TokenUtility.generate_dummy_jwt_token(payload)

    # create otp and the corresponding secret
    if user.otp_secret:
        otp = OTP.generate_otp(user)
        user.save()
    else:
        otp, secret = OTP.generate_secret_with_otp()
        user.otp_secret = secret
        user.save()

    # in case of dry run the otps are a part of logs
    # instead of the emails
    if settings.DRY_RUN:
        print(otp)

    # Send Email
    if purpose == "verify":
        subject = "Verify your account"
        body = f"""OTP to verify your account {otp}
        This otp is valid only for 5 minutes
        """
    elif purpose == "reset-password":
        subject = "OTP to confirm your account"
        body = f"""OTP is {otp}
        This otp is valid only for 5 minutes.
        """
    data = {"subject": subject, "body": body, "to_email": user.email}

    if not settings.DRY_RUN:
        Util.send_email(data)

    return token


# Registering the user with otp verification and directly log in the user
class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]

    @extend_schema(
        request=UserRegistrationSerializer,
        responses={200: UserRegistrationResponseSerializer},
        tags=["auth"],
        auth=[],
    )
    def post(self, request, format=None):
        # validating and creating the user
        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.save()  # creates the abstract user fields

        # defines user login method as local
        user = User.objects.get(email=email)
        user.login_method = "local"
        user.save()

        # if the user is of type job seeker then create a user profile
        if user.user_type == "Job Seeker":
            user_profile = UserProfile(user=user)
            user_profile.save()

        token = generate_guest_token(user, "verify")

        return Response(
            {
                "msg": "OTP Sent Successfully. Please Check your Email",
                "url": "otp/verify/",
                "token": token,
            },
            status=status.HTTP_200_OK,
        )


class OTPVerificationCheckView(APIView):
    renderer_classes = [UserRenderer]

    @extend_schema(
        request=OTPVerificationCheckSerializer,
        tags=["auth"],
        auth=[],
        parameters=[
            OpenApiParameter(
                name="token",
                type=str,
                required=True,
                description="Verification token created while registration.",
            )
        ],
    )
    def post(self, request, format=None):
        dummy_token = request.query_params.get("token")

        try:
            payload = TokenUtility.verify_and_get_payload(dummy_token)
        except InvalidToken as e:
            return Response(
                {"errors": {"token": str(e)}}, status=status.HTTP_401_UNAUTHORIZED
            )
        except TokenError as e:
            return Response(
                {"errors": {"token": str(e)}}, status=status.HTTP_400_BAD_REQUEST
            )

        serializer = OTPVerificationCheckSerializer(
            data=request.data, context={"email": payload.get("email")}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        token = TokenUtility.get_tokens_for_user(user)

        return Response(
            {"msg": "OTP Verified Successfully!", "token": token},
            status=status.HTTP_201_CREATED,
        )


# Login the user and generate JWT token
class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    @extend_schema(
        request=UserLoginSerializer,
        responses={200: UserLoginResponseSerializer},
        tags=["auth"],
        auth=[],
    )
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get("email")
        password = serializer.data.get("password")
        user = authenticate(email=email, password=password)
        if user is not None:
            if user.is_verified:
                token = TokenUtility.get_tokens_for_user(user)
                return Response(
                    {"token": token, "msg": "Login Success", "verify": True},
                    status=status.HTTP_200_OK,
                )
            else:
                token = generate_guest_token(user, "verify")
                return Response(
                    {"msg": "User not verified", "token": token, "verify": False},
                    status=status.HTTP_200_OK,
                )
        else:
            return Response(
                {"errors": {"non_field_errors": ["Email or Password is not valid"]}},
                status=status.HTTP_404_NOT_FOUND,
            )


# Show profile of logged in user
class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: UserSerializer}, tags=["auth"])
    def get(self, request, format=None):
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


# LogOut User
class UserLogOutView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    @extend_schema(tags=["auth"])
    def post(self, request, format=None):
        try:
            refresh_token = request.data["refresh_token"]
            token_obj = RefreshToken(refresh_token)
            token_obj.blacklist()
            return Response(
                {"msg": "LogOut Successfully"},
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"errors": {"msg": str(e)}}, status=status.HTTP_400_BAD_REQUEST
            )


# Password Reset functionality (forget password)
class SendPasswordResetOTPView(APIView):
    renderer_classes = [UserRenderer]

    @extend_schema(request=SendPasswordResetOTPSerializer, tags=["auth"])
    def post(self, request, format=None):
        serializer = SendPasswordResetOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        token = generate_guest_token(user, "reset-password")
        return Response(
            {
                "msg": "OTP Sent Successfully. Please Check your Email",
                "token": token,
            },
            status=status.HTTP_200_OK,
        )


# View for verifying the otp to reset password
class ResetPasswordOtpVerifyView(APIView):
    renderer_classes = [UserRenderer]

    @extend_schema(tags=["auth"])
    def post(self, request, format=None):
        dummy_token = request.query_params.get("token")
        try:
            payload = TokenUtility.verify_and_get_payload(dummy_token)
        except InvalidToken as e:
            return Response(
                {"errors": {"token": str(e)}}, status=status.HTTP_401_UNAUTHORIZED
            )
        except TokenError as e:
            return Response(
                {"errors": {"token": str(e)}}, status=status.HTTP_400_BAD_REQUEST
            )

        serializer = ResetPasswordOtpVerifySerializer(
            data=request.data, context={"email": payload.get("email")}
        )
        serializer.is_valid(raise_exception=True)
        uid = serializer.validated_data["uid"]
        token = serializer.validated_data["token"]
        return Response(
            {"msg": "Verified Successfully!", "token": token, "uid": uid},
            status=status.HTTP_200_OK,
        )


class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]

    @extend_schema(request=UserPasswordResetSerializer, tags=["auth"])
    def post(self, request, format=None):
        uid = request.query_params.get("uid")
        token = request.query_params.get("token")
        serializer = UserPasswordResetSerializer(
            data=request.data, context={"uid": uid, "token": token}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        body = "Your password is successfully changed.\nLogin to your account to access your account."
        data = {"subject": "Reset Your Password", "body": body, "to_email": user.email}
        Util.send_email(data)
        return Response(
            {"msg": "Password Reset Successfully"}, status=status.HTTP_200_OK
        )


# Password Changed functionality with otp verification
class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    @extend_schema(request=UserChangePasswordSerializer, tags=["auth"])
    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(
            data=request.data, context={"user": request.user}
        )
        serializer.is_valid(raise_exception=True)
        return Response(
            {"msg": "OTP Sent Successfully. Please Check your Email"},
            status=status.HTTP_200_OK,
        )


class UserChangePasswordOTPView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    @extend_schema(request=UserChangePasswordOTPSerializer, tags=["auth"])
    def post(self, request, format=None):
        serializer = UserChangePasswordOTPSerializer(
            data=request.data, context={"user": request.user}
        )
        serializer.is_valid(raise_exception=True)

        return Response(
            {"msg": "Password Changed Successfully"}, status=status.HTTP_200_OK
        )


class GoogleHandle(APIView):
    renderer_classes = [UserRenderer]

    def get(self, request):
        # creating a random state
        state = secrets.token_urlsafe(32)

        # defining the sessions params
        params = {
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "scope": "openid email profile",
            "state": state,
            "client_id": settings.GOOGLE_CLIENT_ID,
            "response_type": "code",
        }
        request_url = "{}?{}".format(
            "https://accounts.google.com/o/oauth2/v2/auth",
            urllib.parse.urlencode(params),
        )

        # setting  the state in sessions
        request.session["oauth_token"] = state

        return Response({"google_redirect_url": request_url}, status=status.HTTP_200_OK)


class CallbackHandleView(APIView):
    renderer_classes = [UserRenderer]

    def get(self, request):
        access_token = request.query_params.get("access_token")

        if access_token is None:
            return Response(
                {"error": "Invaid request."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Use the access token to retrieve user information from Google
        user_info_response = requests.get(
            f"https://www.googleapis.com/oauth2/v2/userinfo?access_token={access_token}"
        )
        user_info = user_info_response.json()

        # Extract the email and name from the user information
        email = user_info.get("email", None)
        name = user_info.get("name", None)
        if not email or not name:
            return Response(
                {"error": "Failed to get data from Google user info."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Finding if GoogleCallBack has gmail user
            user_type = ""
            if email.endswith("@gmail.com"):
                user_type = "Job Seeker"
            else:
                user_type = "Employer"

            # Login the user
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "name": name,
                    "login_method": "google_login",
                    "last_verified_identity": datetime.datetime.now(),
                    "user_type": user_type,
                },
            )

            user_instance, user_instance_created = UserProfile.objects.get_or_create(user = user)

            if not created:
                user.last_verified_identity = datetime.datetime.now()
                user.save()

            jwt_token = TokenUtility.get_tokens_for_user(user)
            return Response(
                {"token": jwt_token, "msg": "Success"}, status=status.HTTP_200_OK
            )
        except Exception as e:
            print(e)
            return Response(
                {"msg": "There was an error authenticating the user"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
