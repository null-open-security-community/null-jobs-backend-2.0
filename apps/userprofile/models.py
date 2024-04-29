import uuid

from django.db import models

from apps.accounts.models import User
from apps.userprofile import constants

# Create your models here.


class UserProfile(models.Model):
    """
    Represents a user profile with related details.

    This class defines the attributes associated with a user profile.
    This class has two foreign keys that point to Job and Company table
    """

    def media_upload_path(instance, filename):
        file_path = f"user_{instance.id}/data/{filename}"
        return file_path

    class Meta:
        db_table = constants.DB_TABLE_USER_PROFILE

    # why are uuid fields used instead of the realtions in django
    # this should have been user relation to the accounts in the end
    id = id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        User, unique=True, on_delete=models.CASCADE, editable=False
    )

    age = models.PositiveIntegerField(default=None, null=True)
    gender = models.CharField(
        choices=constants.GENDER, max_length=6, default=None, null=True
    )
    address = models.TextField(max_length=100, null=True, default=None)
    experience = models.CharField(default=0, null=True, max_length=3)
    profession = models.CharField(max_length=100, default=None, null=True)

    # files for the profile
    resume = models.FileField(upload_to=media_upload_path, null=True, default=None)
    profile_picture = models.FileField(
        upload_to=media_upload_path, null=True, default=None
    )
    cover_letter = models.FileField(
        upload_to=media_upload_path, null=True, default=None
    )

    # user profile sections
    about = models.TextField(max_length=100, default=None, null=True)
    education = models.JSONField(default=dict, null=True)
    professional_skills = models.JSONField(default=dict, null=True)
    work_experience = models.JSONField(default=dict, null=True)

    # These fields will be displayed as a part of "contact" field
    phone = models.CharField(max_length=12, default=None, null=True)
    website = models.URLField(default=None, null=True)
    social_handles = models.URLField(default=None, null=True)


class FavoriteProfiles(models.Model):
    """
    This model represents list of favorite profiles
    belong to specific employer
    """

    class Meta:
        db_table = "tbl_favorite_profiles"
        unique_together = [['employer', 'favorite_profile']]

    employer = models.ForeignKey(User, on_delete=models.CASCADE)
    favorite_profile = models.ForeignKey(UserProfile, on_delete=models.CASCADE)

    # time stamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

