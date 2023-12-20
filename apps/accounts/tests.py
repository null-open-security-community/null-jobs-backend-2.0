from django.test import TestCase

# Create your tests here.
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from .models import User
from apps.accounts.serializers import UserRegistrationSerializer  # Replace with actual import path
# from apps.accounts.utils import generate_guest_token  # Replace with actual import path
from apps.accounts.renderers import UserRenderer  # Replace with actual import path



from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework import status
from unittest.mock import patch
from django.contrib.auth import get_user_model

class UserRegistrationViewTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.url = '/register/'

    @patch('apps.accounts.views.generate_guest_token')
    def test_user_registration_successful(self, mock_generate_guest_token):

        # Mocked Token
        mock_generate_guest_token.return_value = "your-token"

        # Create a valid user registration payload
        payload = {
            "email": "Test@gmail.com",
            "name": "Test User",
            "password": "testpassword",
            "password2": "testpassword",
            "user_type": "Employer",
        }

        # Make a POST request to the registration endpoint
        response = self.client.post(self.url, payload, format='json')
        print(response.data)

        # Check if the response is as expected (HTTP 200 OK)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # Check if the response contains the expected message and token
        self.assertIn("OTP Sent Successfully. Please Check your Email", response.data['msg'])
        self.assertIn("token", response.data)
        self.assertEqual(response.data['token'], "your-token")

    def test_user_registration_failure(self):
        # Create an invalid user registration payload
        invalid_payload = {
            "email": "test@gmail.com",
            "name": "Test User",
            "password": "testpassword",
            "password2": "differentpassword",
            "user_type": "Employer",
        }

        # Make a POST request to the registration endpoint with invalid payload
        response = self.client.post(self.url, invalid_payload, format='json')

        # Check if the response is as expected (HTTP 400 Bad Request)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        print(response.data)

        # Check if the response contains the expected error message
        self.assertIn("Password and Confirm Password doesn't match", response.data['non_field_errors'])
