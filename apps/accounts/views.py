import datetime

# from django.urls import reverse
import urllib.parse

import requests
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from apps.accounts.models import *
from apps.accounts.renderers import UserRenderer
from apps.accounts.serializers import *
from apps.accounts.utils import *
from apps.jobs.models import User as user_profile

# from django.shortcuts import render


# #google auth
# from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
# from allauth.socialaccount.providers.oauth2.client import OAuth2Client
# from dj_rest_auth.registration.views import SocialLoginView


def otp_dummy_token(user, purpose):
    """Generate dummy jwt token & send it"""

    payload = {
        "email": user.email,
        "user_id": user.user_id.hex,
        "user_type": user.user_type,
    }

    try:
        token = GenerateToken.generate_dummy_jwt_token(payload)

        # for old user
        if user.otp_secret:
            try:
                otp = OTP.generate_otp(user)
                user.save()
            except Exception as err:
                raise Exception(
                    f"Exception occurred in 'otp_dummy_token' while generating OTP: {err}"
                )

        # for new user
        else:
            try:
                otp, secret = OTP.generate_secret_with_otp()
                user.otp_secret = secret
                user.save()
            except Exception as err:
                raise Exception(
                    f"Exception occurred in 'otp_dummy_token' while generating secret: {err}"
                )

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

        try:
            Util.send_email(data)
        except Exception as err:
            raise Exception(
                f"Exception occurred in 'otp_dummy_token' while sending email: {err}"
            )
        return token

    except Exception as err:
        raise Exception(f"Exception occurred in 'otp_dummy_token': {err}")


# Generate token Manually
class GenerateToken:
    """
    This class deals with token, and its related operations.
    1. Generate token
    2. Verify token
    """

    @staticmethod
    def get_tokens_for_user(user):
        """Generated a dict of access/refresh token"""

        if not user:
            raise Exception("user data not valid")

        try:
            refresh = RefreshToken.for_user(user)
            # custom_payload={"name":user.name,"email":user.email}
            # refresh.payload.update(custom_payload)

            return {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }

        except Exception:
            raise Exception(
                "Exception occurred in 'get_tokens_for_user' while generating refresh token"
            )

    @staticmethod
    def generate_dummy_jwt_token(Cpayload: dict):
        """creating custom payload with 5 minutes expiration time"""

        if isinstance(Cpayload, dict):
            raise Exception("Invalid payload data type")

        custom_payload = {
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        }
        custom_payload.update(Cpayload)
        # Create a new AccessToken with the custom payload
        access_token = AccessToken()
        access_token.payload.update(custom_payload)
        return str(access_token)

    @staticmethod
    def add_payload(token, payload):
        """Add payload to the access token"""

        try:
            access_token = AccessToken(token)
            access_token.payload.update(payload)
            return str(access_token)

        except Exception as err:
            raise Exception(f"Exception occurred in 'add_payload': {err}")

    @staticmethod
    def verify_and_get_payload(token):
        """Token verification"""

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
        except Exception as err:
            # any other exception occurs
            raise Exception(f"Exception occurred in 'verify_and_get_payload': {err}")


class UserRegistrationView(APIView):
    """
    Registering the user with otp verification and directly log in the user
    """

    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        """
        Saves the user data into the database, this method
        saves the user data into two tables i.e., tbl_user_profile and tbl_user_auth
        """

        serializer = UserRegistrationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.save()

        user = User.objects.get(email=email)
        user.provider = "local"
        try:
            token = otp_dummy_token(user, "verify")
        except Exception:
            return Response(
                {"msg": "Something Went Wrong"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        # Add an entry in the tbl_user_profile with dummy data
        dummy_data = {
            "user_id": user.user_id.hex,
            "name": user.name,
            "email": user.email,
            "user_type": user.user_type,
            "about": None,
        }

        user_instance = user_profile(**dummy_data)
        user_instance.custom_save(override_uuid={"uuid": dummy_data["user_id"]})

        return Response(
            {
                "msg": "OTP Sent Successfully. Please Check your Email",
                "url": "otp/verify/",
                "token": token,
            },
            status=status.HTTP_200_OK,
        )


class OTPVerificationCheckView(APIView):
    """
    Verify and generate the token for the user
    """

    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        """
        Method to be executed on POST Request
        """

        dummy_token = request.query_params.get("token")
        try:
            payload = GenerateToken.verify_and_get_payload(dummy_token)
            # print(payload)
        except (InvalidToken, TokenError) as e:
            error_status = (
                status.HTTP_401_UNAUTHORIZED
                if isinstance(e, InvalidToken)
                else status.HTTP_400_BAD_REQUEST
            )
            return Response({"errors": {"token": str(e)}}, status=error_status)
        except Exception as e:
            return Response(
                {"errors": {"token": str(e)}}, status=status.HTTP_400_BAD_REQUEST
            )

        serializer = OTPVerificationCheckSerializer(
            data=request.data, context={"email": payload.get("email")}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        try:
            token = GenerateToken.get_tokens_for_user(user)
            return Response(
                {"msg": "OTP Verified Successfully!", "token": token},
                status=status.HTTP_201_CREATED,
            )
        except Exception:
            return Response(
                {"msg": "Token Not Generated"}, status=status.HTTP_400_BAD_REQUEST
            )


# Login the user and generate JWT token
class UserLoginView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get("email")
        password = serializer.data.get("password")
        user = authenticate(email=email, password=password)
        if user is not None:
            try:
                if user.is_verified:
                    token = GenerateToken.get_tokens_for_user(user)
                    message = "Login Success"
                    verify = True
                else:
                    token = otp_dummy_token(user)
                    message = "User not verified"
                    verify = False
            except Exception:
                return Response(
                    {"msg": "Something Went Wrong"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        else:
            return Response(
                {"errors": {"non_field_errors": ["Email or Password is not valid"]}},
                status=status.HTTP_404_NOT_FOUND,
            )

        return Response(
            {"token": token, "msg": message, "verify": verify},
            status=status.HTTP_200_OK,
        )


class UserProfileView(APIView):
    """
    Show profile of logged in user
    """

    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        """Method to be called on GET Request"""

        serializer = UserProfileSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UserLogOutView(APIView):
    """Log out user view"""

    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        "Method to be called on POST Request"

        try:
            # token = request.META['HTTP_AUTHORIZATION'].split(' ')[1]
            # print(token)
            # access_token = AccessToken(token)
            # access_token.set_exp(lifetime=datetime.timedelta(minutes=1))
            # print(access_token)
            # breakpoint()
            refresh_token = request.data["refresh_token"]
            token_obj = RefreshToken(refresh_token)
            token_obj.blacklist()
            return Response(
                {
                    "msg": "LogOut Successfully",
                    # "token":access_token,
                },
                status=status.HTTP_200_OK,
            )
        except Exception as e:
            return Response(
                {"errors": {"msg": str(e)}}, status=status.HTTP_400_BAD_REQUEST
            )


class SendPasswordResetOTPView(APIView):
    """
    Password Reset functionality (forget password)
    """

    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        """Method to be executed on post request"""

        serializer = SendPasswordResetOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        try:
            token = otp_dummy_token(user, "reset-password")
        except Exception:
            return Response(
                {"msg": "Something Went Wrong"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        return Response(
            {
                "msg": "OTP Sent Successfully. Please Check your Email",
                "token": token,
            },
            status=status.HTTP_200_OK,
        )


class ResetPasswordOtpVerifyView(APIView):
    """
    Password Reset functionality (forget password)
    """

    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        """Method to be executed on post request"""

        dummy_token = request.query_params.get("token")
        try:
            payload = GenerateToken.verify_and_get_payload(dummy_token)
        except (InvalidToken, TokenError) as e:
            error_status = (
                status.HTTP_401_UNAUTHORIZED
                if isinstance(e, InvalidToken)
                else status.HTTP_400_BAD_REQUEST
            )
            return Response({"errors": {"token": str(e)}}, status=error_status)

        try:
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
        except Exception:
            raise Exception(
                {"msg": "Something Went Wrong"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        if not request.query_params:
            return Response(
                {"msg": "no query parameters supplied"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        uid = request.query_params.get("uid")
        token = request.query_params.get("token")

        if not uid or not token:
            return Response(
                {"msg": "uid and token is missing"}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            serializer = UserPasswordResetSerializer(
                data=request.data, context={"uid": uid, "token": token}
            )
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data["user"]
            body = "Your password is successfully changed.\nLogin to your account to access your account."
            data = {
                "subject": "Reset Your Password",
                "body": body,
                "to_email": user.email,
            }
            Util.send_email(data)
            return Response(
                {"msg": "Password Reset Successfully"}, status=status.HTTP_200_OK
            )
        except Exception:
            return Response(
                {"msg": "Something went wrong"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class UserChangePasswordView(APIView):
    """
    Password Changed functionality with otp verification
    """

    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        """Method to be executed on post request"""

        if not request.data:
            return Response(
                {"msg": "Empty POST request body supplied"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            serializer = UserChangePasswordSerializer(
                data=request.data, context={"user": request.user}
            )
            serializer.is_valid(raise_exception=True)
            return Response(
                {"msg": "OTP Sent Successfully. Please Check your Email"},
                status=status.HTTP_200_OK,
            )
        except:
            return Response(
                {"msg": "Something Went Wrong"}, status=status.HTTP_400_BAD_REQUEST
            )


class UserChangePasswordOTPView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        if not request.data:
            return Response(
                {"msg": "Empty POST request body supplied"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            serializer = UserChangePasswordOTPSerializer(
                data=request.data, context={"user": request.user}
            )
            serializer.is_valid(raise_exception=True)

            return Response(
                {"msg": "Password Changed Successfully"}, status=status.HTTP_200_OK
            )
        except Exception:
            return Response(
                {"msg": "Something went wrong"}, status=status.HTTP_400_BAD_REQUEST
            )


# Hit on that url to get the callback
# https://accounts.google.com/o/oauth2/v2/auth?client_id=<google-client-id>&response_type=code&scope=https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile&access_type=offline&redirect_uri=http://localhost:8000/api/user/google/login/callback/


class GoogleHandle(APIView):
    renderer_classes = [UserRenderer]

    def get(self, request):
        client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
        response_type = "code"
        scope = f"https://www.googleapis.com/auth/userinfo.email "
        scope += f"https://www.googleapis.com/auth/userinfo.profile"
        access_type = "offline"
        redirect_uri = settings.GOOGLE_REDIRECT_URI

        google_redirect_url = "https://accounts.google.com/o/oauth2/v2/auth"
        google_redirect_url += f"?client_id={urllib.parse.quote(client_id)}"
        google_redirect_url += f"&response_type={urllib.parse.quote(response_type)}"
        google_redirect_url += f"&scope={urllib.parse.quote(scope)}"
        google_redirect_url += f"&access_type={urllib.parse.quote(access_type)}"
        google_redirect_url += f"&redirect_uri={urllib.parse.quote(redirect_uri)}"
        return Response(
            {"google_redirect_url": google_redirect_url}, status=status.HTTP_200_OK
        )


class CallbackHandleView(APIView):
    renderer_classes = [UserRenderer]

    def get(self, request):
        code = request.query_params.get("code")

        if not code:
            return Response(
                {"msg": "Expected a non-empty value of parameter 'code'"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        data = {
            "code": code,
            "client_id": os.environ.get("GOOGLE_OAUTH_CLIENT_ID"),
            "client_secret": os.environ.get("GOOGLE_OAUTH_SECRET"),
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }

        token_response = requests.post("https://oauth2.googleapis.com/token", data=data)
        if token_response.status_code != 200:
            return Response(
                {"error": f"Failed to communicate with Google"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        token_data = token_response.json()

        if "error" in token_data:
            return Response(
                {"error": "Failed to get access token from Google."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Get the access token from the response
        access_token = token_data.get("access_token", None)
        # print(access_token)
        if not access_token:
            return Response(
                {"error": "Failed to get access token from Google response."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Use the access token to retrieve user information from Google
        user_info_response = requests.get(
            f"https://www.googleapis.com/oauth2/v2/userinfo?access_token={access_token}"
        )
        user_info = user_info_response.json()
        # print(user_info)
        # Extract the email and name from the user information
        email = user_info.get("email", None)
        name = user_info.get("name", None)
        if not email:
            return Response(
                {"error": "Failed to get email from Google user info."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not name:
            return Response(
                {"error": "Failed to get name from Google user info."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Login the user
            user = User.objects.get(email=email)
            try:
                jwt_token = GenerateToken.get_tokens_for_user(user)
                return Response(
                    {"token": jwt_token, "msg": "Login Success"},
                    status=status.HTTP_200_OK,
                )
            except:
                return Response(
                    {"msg": "Token Not Generated"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        except User.DoesNotExist:
            userdata = {"email": email, "name": name}
            serializer = GoogleAuthSerializer(
                data=request.data, context={"userdata": userdata}
            )
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            user.provider = "google"
            user.is_verified = True
            user.save()
            try:
                token = GenerateToken.get_tokens_for_user(user)
                return Response(
                    {"msg": "Registration Completed", "token": token},
                    status=status.HTTP_201_CREATED,
                )
            except:
                return Response(
                    {"msg": "Something Went Wrong"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        except:
            return Response(
                {"errors": "Invalid user"}, status=status.HTTP_400_BAD_REQUEST
            )


class RestrictedPage(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated] if settings.ENABLE_AUTHENTICATION else []

    def get(self, request, format=None):
        return Response({"msg": "I am a restricted page"}, status=status.HTTP_200_OK)
