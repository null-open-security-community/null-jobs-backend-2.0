import uuid

from django.db import models

from apps.accounts.models import User
from apps.jobs.constants import values
from apps.jobs.constants.values import GENDER, HIRING_STATUS, JOB_TYPE, STATUS_CHOICES


class Company(models.Model):
    """
    Represents a company with related details.

    This class defines the attributes associated with a company, and
    belongs to the company table in the database
    """

    def media_upload_path(instance, filename):
        file_path = f"user_{instance.creator.id}/data/company_{filename}"
        return file_path

    class Meta:
        db_table = values.DB_TABLE_COMPANY

    company_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    # creator of the compnau is the user who is hiring for it
    creator = models.ForeignKey(
        User, on_delete=models.CASCADE, unique=True, editable=False
    )

    name = models.CharField(max_length=255, null=False)
    picture = models.FileField(null=True, default=None, upload_to=media_upload_path)
    email_id = models.EmailField(null=True, default=None)
    location = models.CharField(max_length=255, null=False)
    contact_no = models.CharField(max_length=255, default=None, null=True)

    team_members = models.PositiveIntegerField(default=False, null=True)
    founded_year = models.PositiveIntegerField(default=False, null=False)

    address = models.CharField(max_length=255, default=None, null=True)

    social_profiles = models.URLField(default=None, null=True)

    about = models.TextField(max_length=500, default=False, null=False)
    short_story = models.TextField(max_length=500, default=None, null=True)
    speciality = models.TextField(max_length=500, default=None, null=True)

    # deletion check for the company should not be present as on delete
    # of the user auth the company will be deleted as well as there is cascade
    # policy
    is_deleted = models.BooleanField(default=False, editable=False)


class Job(models.Model):
    """
    Represents a job posting with related details.

    This class defines the attributes associated with a job posting,
    This class has one foreign field, rest are the normal fields.
    """

    class Meta:
        db_table = values.DB_TABLE_JOBS

    job_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False, null=False
    )

    # relations to the user and the company as the jobs are posted by
    # a particular user and the company is more of a employer profile mapping
    company = models.ForeignKey(
        Company, on_delete=models.CASCADE, related_name="company", editable=False
    )
    employer = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="employer", editable=False
    )  # why is this a uuid field and not a relation

    job_role = models.CharField(max_length=100, null=False)
    location = models.CharField(max_length=100, default=None)
    experience = models.IntegerField(default=0, null=False)
    job_type = models.CharField(max_length=80, choices=JOB_TYPE, null=False)
    vacancy_position = models.IntegerField(default=None, null=False)
    industry = models.CharField(max_length=50, default=None, null=False)
    category = models.CharField(max_length=20, default=None, null=True)

    # creation and updation dates
    created_at = models.DateTimeField(auto_now_add=True)  # only add the timestamp once
    updated_at = models.DateTimeField(auto_now=True)  # update timestamp on every save()

    # flags are un explained here
    is_active = models.BooleanField(default=False, null=False, editable=False)
    is_created = models.BooleanField(default=False, null=True, editable=False)
    is_deleted = models.BooleanField(default=False, null=True, editable=False)
    is_featured = models.BooleanField(default=False, null=True)

    # These fields will be displayed as a part of "description" field and the
    # body of the job
    job_responsibilities = models.TextField(
        default="No Job Responsibilities provided", max_length=1000
    )
    skills_required = models.TextField(
        default="No skills details provided", max_length=1000
    )
    education_or_certifications = models.TextField(
        default="No Education details provided", max_length=1000
    )
    about = models.TextField(default="No description provided", max_length=500)


class ContactMessage(models.Model):
    """Represents contact_us model.
    defines the attributes of the contact_us page feilds.
    """

    class Meta:
        db_table = "tbl_contact_us"

    full_name = models.CharField(max_length=100)
    email = models.EmailField()
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.full_name
