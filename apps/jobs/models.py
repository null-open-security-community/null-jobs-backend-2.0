import uuid

from django.db import models

from apps.accounts.models import User as UserAuth

STATUS_CHOICES = (
    ("under-reviewed", "Under-Reviewed"),
    ("shortlisted", "Shortlisted"),
    ("accepted", "Accepted"),
    ("rejected", "Rejected"),
    ("on-hold", "On-Hold"),
)

USER_TYPE = (("Job Seeker", "User/Employee"), ("Employer", "HR/Employer"))


def hex_uuid():
    return uuid.uuid4().hex


class Company(models.Model):
    """
    Represents a company with related details.

    This class defines the attributes associated with a company, and
    belongs to the company table in the database
    """

    class Meta:
        db_table = "tbl_company"

    name = models.CharField(max_length=255, null=False)
    location = models.CharField(max_length=255, null=False)
    about = models.TextField(max_length=500, default=None)
    company_id = models.UUIDField(
        primary_key=True, default=hex_uuid, editable=False
    )  # uuid1 uses network address for random number, so it's better to use uuid4

    def __str__(self):
        return self.name


class Job(models.Model):
    """
    Represents a job posting with related details.

    This class defines the attributes associated with a job posting,
    This class has one foreign field, rest are the normal fields.
    """

    class Meta:
        db_table = "tbl_job"

    job_id = models.UUIDField(
        primary_key=True, default=hex_uuid, editable=False, null=False
    )
    job_role = models.CharField(max_length=100, null=False)
    company = models.ForeignKey(
        Company, on_delete=models.CASCADE, related_name="companyies", null=False
    )
    description = models.TextField(default="No description provided", max_length=500)
    location = models.CharField(max_length=100, default=None)
    post_date = models.DateField(null=False)
    posted = models.BooleanField(default=False, null=False)
    experience = models.IntegerField(default=0, null=False)
    created_at = models.DateTimeField(auto_now_add=True)  # only add the timestamp once
    updated_at = models.DateTimeField(auto_now=True)  # update timestamp on every save()
    employer_id = models.UUIDField(null=False, editable=True)

    def __str__(self):
        return self.job_role


class User(models.Model):
    """
    Represents a user profile with related details.

    This class defines the attributes associated with a user profile.
    This class has two foreign keys that point to Job and Company table
    """

    class Meta:
        db_table = "tbl_user_profile"

    user_id = models.UUIDField(
        primary_key=True, default=hex_uuid, editable=False, null=False
    )
    name = models.CharField(max_length=30, null=False)
    email = models.CharField(max_length=30, null=False)
    address = models.TextField(max_length=100, null=False)
    phone = models.CharField(max_length=12, default=None, null=True)
    about = models.TextField(max_length=100, default=None)
    job = models.ForeignKey(Job, on_delete=models.CASCADE, null=True, default=None)
    resume = models.FileField(upload_to="resume/", null=True, default=None)
    profile_picture = models.FileField(
        upload_to="profile_picture/", null=True, default=None
    )
    cover_letter = models.FileField(upload_to="cover_letter/", null=True)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, null=False)
    user_type = models.CharField(max_length=15, choices=USER_TYPE, null=False)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if self.resume:
            self.resume_file_path = self.resume.path
        else:
            self.resume_file_path = ""
        super().save(*args, **kwargs)


class Applicants(models.Model):
    """Represents apply job model.
    Currently not assigning job_id as the primary key
    """

    class Meta:
        db_table = "tbl_applicants"

    job = models.ForeignKey(Job, on_delete=models.CASCADE, null=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=False)
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default="applied")
    created_at = models.DateTimeField(auto_now_add=True)
    resume = models.FileField(upload_to="resume/", null=True, blank=True)
    cover_letter = models.FileField(upload_to="cover_letters/", null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_deleted = models.BooleanField(default=False, null=True)
    is_active = models.BooleanField(default=True, null=True)
    employer_id = models.UUIDField(null=False, editable=False, default=None)
