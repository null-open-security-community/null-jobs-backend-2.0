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
    id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, null=False, unique=True
    )
    email = models.EmailField(
        verbose_name="Email",
        max_length=255,
        unique=True,
    )
    name = models.CharField(max_length=200)
    provider = models.CharField(max_length=50, null=True)
    # uuid = models.ForeignKey(JobUser, on_delete=models.CASCADE)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    otp = models.CharField(max_length=6, null=True)
    otp_secret = models.CharField(max_length=200, null=True)
    dummy_password = models.CharField(max_length=200, null=True)
    user_type = models.CharField(max_length=12, choices=USER_TYPE, null=False)
    last_verified_identity = models.DateTimeField(
        auto_now=False, auto_now_add=False, null=True
    )
    login_method = models.CharField(max_length=50, null=True)
    is_moderator = models.BooleanField(default=False, null=True)

    objects = UserManager()

    USERNAME_FIELD = "email"  # by default required
    REQUIRED_FIELDS = ["name"]

    class Meta:
        app_label = "accounts"
        db_table = "tbl_user_auth"

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        "Does the user have a specific permission?"
        # Simplest possible answer: Yes, always
        return self.is_admin

    def has_module_perms(self, app_label):
        "Does the user have permissions to view the app `app_label`?"
        # Simplest possible answer: Yes, always
        return True

    @property
    def is_staff(self):
        "Is the user a member of staff?"
        # Simplest possible answer: All admins are staff
        return self.is_admin
