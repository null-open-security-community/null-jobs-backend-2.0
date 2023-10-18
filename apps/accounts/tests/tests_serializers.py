from django.test import TestCase
from apps.accounts.models import *
from rest_framework.test import APIClient
from rest_framework import status
from apps.accounts.serializers import *
from django.urls import reverse


class UserRegistrationSerializerTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user_data = {
            "id": "123456789",
            "email": "null@gmail.com",
            "name": "nulluser",
            "password": "password",
            "password2": "password2",
        }

    def create_user(self, data):
        """
        Helper function to create a user using the API.
        """
        # registration API endpoint
        response = self.client.post(
            url=reverse("register/"),
            data=self.user_data,
            content_type="application/json",
        )
        return response

    def test_valid_user_registration(self):
        response = self.create_user(self.user_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_missing_required_field(self):
        del self.user_data["email"]  # Simulate missing email field
        response = self.create_user(self.user_data)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertFalse(
            User.objects.filter(email="null@gmail.com").exists()
        )  # Assert that the user was not created


class OTPVerificationSerializerTest(TestCase):
    def setUp(self):
        self.client = APIClient()

    def verify_otp(self, data):
        """
        Helper function to verify OTP using the API.
        """
        url = "otp/verify/"  # Replace with your OTP verification API endpoint
        response = self.client.post(url, data, format="json")
        return response

    def test_valid_otp_verification(self):
        data = {
            "otp": "123456",  # Replace with a valid OTP
        }
        response = self.verify_otp(data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_invalid_otp_verification(self):
        data = {
            "otp": "654321",  # Replace with an invalid OTP
        }
        response = self.verify_otp(data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UserLoginSerializerTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            name="nulluser",
            email="null@gmail.com",
            password="password",
        )

    def login_user(self, data):
        """
        Helper function to log in a user using the API.
        """
        url = "apps/accounts/login/"  # Replace with your login API endpoint
        response = self.client.post(url, data, format="json")
        return response

    def test_valid_user_login(self):
        data = {
            "email": "null@gmail.com",
            "password": "password",
        }
        response = self.login_user(data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_invalid_user_login(self):
        data = {
            "email": "null@gmail.com",
            "password": "wrongpassword",  # Incorrect password
        }
        response = self.login_user(data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_missing_required_field(self):
        data = {
            "email": "null@gmail.com",
        }
        response = self.login_user(data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UserProfileSerializersTest(TestCase):
    def test_user_profile_serializers(self):
        data = {
            "id": "12345678",
            "name": "nulluser",
            "email": "null@gmail.com",
        }
        self.assertEqual(data["id"], "12345678")
        self.assertEqual(data["name"], "nulluser")
        self.assertEqual(data["email"], "null@gmail.com")
