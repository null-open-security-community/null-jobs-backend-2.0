import unittest
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.messages import get_messages
from views import *

User = get_user_model()


class UserRegistrationTestCase(TestCase):
    def setUp(self):
        self.user_data = {
            "username": "nulluser",
            "email": "null@gmail.com",
            "password1": "password",
            "password2": "tpassword",
        }

    def test_user_registration_view(self):
        """Test user registration view."""

        response = self.client.post(
            self.registration_url, data=self.user_data, follow=True
        )

        # Check if registration was successful and the user is logged in
        self.assertEqual(response.status_code, 200)
        self.assertRedirects(
            response, reverse("api/accounts/register")
        )  # Replace 'api/accounts/register' with the actual redirect URL upon successful registration

        # Check if the user is created
        self.assertTrue(User.objects.filter(username="testuser").exists())

        # Check if a success message is displayed
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(
            str(messages[0]), "Registration successful. You are now logged in."
        )

    def test_user_registration_failure(self):
        """Test user registration failure (e.g., mismatched passwords)."""
        self.user_data["password2"] = "wrongpassword"
        response = self.client.post(
            self.registration_url, data=self.user_data, follow=True
        )

        # Check if registration failed and the user is not logged in
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response, "registration/registration_form.html"
        )  # Check if the registration form template is rendered
        self.assertFalse(
            User.objects.filter(username="testuser").exists()
        )  # User should not be created

        # Check if an error message is displayed
        messages = list(get_messages(response.wsgi_request))
        self.assertEqual(len(messages), 1)
        self.assertEqual(
            str(messages[0]), "Registration failed. Please correct the errors below."
        )


if __name__ == "__main__":
    unittest.main()
