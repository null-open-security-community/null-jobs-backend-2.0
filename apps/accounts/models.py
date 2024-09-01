import uuid

from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models

# from Jobapp.models import User as JobUser
# Create your models here.

USER_TYPE = (("Job Seeker", "User/Employee"), ("Employer", "HR/Employer"), ("Moderator", "Admin/Moderator"))


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
            user_type="Moderator"  # keep it as it is
        )
        user.is_admin = True
        user.is_staff = True
        user.is_moderator = True
        user.is_verified = True
        user.save(using=self._db)
        return user

    # todo: to have it when we have moderator dashboard
    def create_moderator(self, email, name, password=None):
        """
        Creates and saves a superuser with the given email, name, tc and password.
        """
        user = self.create_user(
            email,
            password=password,
            name=name,
            user_type="Moderator" # as it moderator
        )
        #
        user.is_admin = False # false
        user.is_staff = True
        user.is_moderator = True
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

    is_staff = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    otp = models.CharField(max_length=6, null=True)
    otp_secret = models.CharField(max_length=200, null=True)
    dummy_password = models.CharField(max_length=200, null=True)
    user_type = models.CharField(max_length=12, choices=USER_TYPE, null=False)

    # could be google or local
    last_verified_identity = models.DateTimeField(
        auto_now=False, auto_now_add=False, null=True
    )
    login_method = models.CharField(max_length=50, null=True)

    objects = UserManager()

    USERNAME_FIELD = "email"  # by default required
    REQUIRED_FIELDS = ["name"]

    class Meta:
        db_table = "tbl_user_auth"


    def get_full_name(self):
        # The user is identified by their email address
        return self.email

    def get_short_name(self):
        # The user is identified by their email address
        return self.email

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return True

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff_member(self):
        "Is the user a member of staff?"
        return self.is_staff

    @property
    def is_admin_member(self):
        "Is the user a admin member?"
        return self.is_admin

