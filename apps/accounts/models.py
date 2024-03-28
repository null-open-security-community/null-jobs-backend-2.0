import uuid

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models

# from Jobapp.models import User as JobUser
# Create your models here.

USER_TYPE = (("Job Seeker", "User/Employee"), ("Employer", "HR/Employer"))


class UserManager(BaseUserManager):
    def create_user(self, email, name, user_type, password=None, password2=None):
        """
        Creates and saves a User with the given email, name, tc and password.
        """
        if not email:
            raise ValueError("Users must have an email address")

        user = self.model(
            email=self.normalize_email(email), name=name, user_type=user_type
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, name, password=None):
        """
        Creates and saves a superuser with the given email, name, tc and password.
        """
        user = self.create_user(
            email,
            password=password,
            name=name,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=200)

    is_profile_completed = models.BooleanField(default=False, editable=False)
    is_verified = models.BooleanField(default=False, editable=False)
    is_active = models.BooleanField(default=True, editable=False)
    is_admin = models.BooleanField(default=False, editable=False)
    is_moderator = models.BooleanField(default=False, null=True, editable=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    otp = models.CharField(max_length=6, null=True)
    otp_secret = models.CharField(max_length=200, null=True)
    dummy_password = models.CharField(max_length=200, null=True)
    user_type = models.CharField(max_length=12, choices=USER_TYPE, null=False)

    # could be google or local
    last_verified_identity = models.DateTimeField(auto_now=False, auto_now_add=False, null=True)
    login_method = models.CharField(max_length=50, null=True)
    

    objects = UserManager()

    USERNAME_FIELD = "email"  # by default required
    REQUIRED_FIELDS = ["name"]

    class Meta:
        db_table = "tbl_user_auth"

