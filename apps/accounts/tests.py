from unittest.mock import patch

from django.contrib.auth import get_user_model

# Create your tests here.
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

# from apps.accounts.utils import generate_guest_token  # Replace with actual import path
from apps.accounts.renderers import UserRenderer  # Replace with actual import path
from apps.accounts.serializers import (
    UserRegistrationSerializer,  # Replace with actual import path
)

from .models import User


class UserRegistrationViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = "/register/"

    @patch("apps.accounts.views.generate_guest_token")
    def test_user_registration_successful(self, mock_generate_guest_token):
        # Mocked Token
        mock_generate_guest_token.return_value = "your-token"

        # Create a valid user registration payload
        payload = {
            "email": "test@gmail.com",
            "name": "Test User",
            "password": "Test@12345",
            "password2": "Test@12345",
            "user_type": "Employer",
        }

        # Make a POST request to the registration endpoint
        response = self.client.post(self.url, payload, format="json")

        # Check if the response is as expected (HTTP 200 OK)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check if the response contains the expected message and token
        self.assertIn(
            "OTP Sent Successfully. Please Check your Email", response.data["msg"]
        )
        self.assertIn("token", response.data)
        self.assertEqual(response.data["token"], "your-token")
