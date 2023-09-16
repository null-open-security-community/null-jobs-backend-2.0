from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import DjangoUnicodeDecodeError, force_bytes, smart_str
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import serializers

from apps.accounts.models import User
from apps.accounts.utils import *


# User registration
class UserRegistrationSerializer(serializers.ModelSerializer):
    # We are writing this because  we need confirm password field in our Registration request
    password2 = serializers.CharField(style={"input_type": "password"}, write_only=True)

    class Meta:
        model = User
        fields = ["email", "name", "password", "password2"]
        extra_kwargs = {"password": {"write_only": True}}

    # Validating Password and Confirm Password
    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")
        if password != password2:
            raise serializers.ValidationError(
                "Password and Confirm Password doesn't match"
            )
        return attrs

    def create(self, validate_data):
        # print(validate_data)
        return User.objects.create_user(**validate_data)


class OTPVerificationCheckSerializer(serializers.Serializer):
    # email = serializers.EmailField(max_length=255)
    otp = serializers.CharField(max_length=6, style={"input_type": "text"})

    class Meta:
        fields = ["otp"]

    def validate(self, attrs):
        try:
            email = self.context.get("email")
            otp_value = attrs.get("otp")

            user = User.objects.get(email=email)

            if OTP.verify_otp(user, otp_value):
                user.is_verified = True
                user.save()
            else:
                raise serializers.ValidationError("Invalid OTP")

            attrs["user"] = user
            return attrs

        except User.DoesNotExist:
            raise serializers.ValidationError("User not found")


# Login the user
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        model = User
        fields = ["email", "password"]


# Serializer for showing User profile
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "email", "name"]


# Serializer for sending the email to user for reset password
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ["email"]

    def validate(self, attrs):
        email = attrs.get("email")
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            # urlsafe... only accepts bytes but uid is a number so we used force_bytes to convert uid into bytes
            uid = urlsafe_base64_encode(force_bytes(user.id))
            # print("Encoded UID", uid)
            token = PasswordResetTokenGenerator().make_token(user)
            # print("Password Reset Token", token)
            link = "http://localhost:3000/api/user/reset/" + uid + "/" + token
            # print("Password Reset Link", link)
            # Send Email
            body = "Click the link below to Reset Your Password " + link
            data = {"subject": "Reset Your Password", "body": body, "to_email": email}
            Util.send_email(data)
            return attrs
        else:
            raise serializers.ValidationError("You are not a Registered User")


# Serializer for updating the new password
class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )
    password2 = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )

    class Meta:
        fields = ["password", "password2"]

    def validate(self, attrs):
        try:
            password = attrs.get("password")
            password2 = attrs.get("password2")
            uid = self.context.get("uid")
            token = self.context.get("token")
            if password != password2:
                raise serializers.ValidationError(
                    "Password and Confirm Password doesn't match"
                )
            id = urlsafe_base64_decode(smart_str(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError("Token is not valid or Expired")
            if user.check_password(password):
                raise serializers.ValidationError(
                    "New Password can't be same as old password"
                )
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError("Token is not valid or Expired")


# Serializer for providing change password functionality to logged in user
class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )
    password2 = serializers.CharField(
        max_length=255, style={"input_type": "password"}, write_only=True
    )

    class Meta:
        fields = ["password", "password2"]

    def validate(self, attrs):
        password = attrs.get("password")
        password2 = attrs.get("password2")
        user = self.context.get("user")

        if password != password2:
            raise serializers.ValidationError(
                "Password and Confirm Password doesn't match"
            )
        # user.set_password(password)
        # user.save()
        if user.check_password(password):
            raise serializers.ValidationError(
                "New Password can't be same as old password"
            )
        user.dummy_password = password
        otp = OTP.generate_otp(user)
        user.save()
        # Send Email
        body = f"""Confirm OTP to change your password {otp}
This otp is valid only for 5 minutes
"""
        data = {"subject": "Change Password", "body": body, "to_email": user.email}
        Util.send_email(data)
        return attrs


class UserChangePasswordOTPSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=6, style={"input_type": "text"})

    class Meta:
        fields = ["otp"]

    def validate(self, attrs):
        try:
            user = self.context.get("user")
            otp_value = attrs.get("otp")

            if OTP.verify_otp(user, otp_value):
                password = user.dummy_password
                user.set_password(password)
                user.dummy_password = ""
                user.save()

            else:
                raise serializers.ValidationError("Invalid OTP")

            return attrs

        except:
            raise serializers.ValidationError("OTP expired. Please try again")


class GoogleAuthSerializer(serializers.Serializer):
    class Meta:
        model = User
        fields = ["email", "name"]

    def validate(self, attrs):
        user_data = self.context.get("userdata")
        password = User.objects.make_random_password()
        user_data["password"] = password
        return user_data

    def create(self, validate_data):
        return User.objects.create_user(**validate_data)
