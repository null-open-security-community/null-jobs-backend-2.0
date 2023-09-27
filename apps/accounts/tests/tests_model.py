# accounts/tests/test_models.py
from django.test import TestCase
from django.contrib.auth import get_user_model
from models import *

User = get_user_model()


class UserModelTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="null@gmail.com", username="nullUser", password="password"
        )

    def test_create_user(self):
        """Test creating a new user."""
        self.assertEqual(self.user.email, "null@gmail.com")
        self.assertEqual(self.user.username, "nullUser")
        self.assertTrue(self.user.is_active)
        self.assertFalse(self.user.is_staff)
        self.assertFalse(self.user.is_superuser)

    def test_create_superuser(self):
        """Test creating a new superuser."""
        superuser = User.objects.create_superuser(
            email="nulladmin@gmail.com", username="adminuser", password="password"
        )
        self.assertTrue(superuser.is_superuser)
        self.assertTrue(superuser.is_staff)

