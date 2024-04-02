
import uuid
from django.db import models

from apps.userprofile.models import UserProfile
from apps.jobs.models import Job
from apps.applicants import constants



# Create your models here.

class Applicants(models.Model):
    """Represents apply job model.
    Currently not assigning job_id as the primary key
    """

    class Meta:
        db_table = "tbl_applicants"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    job = models.ForeignKey(Job, on_delete=models.CASCADE, null=False)
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE, null=False)
    status = models.CharField(max_length=30, choices=constants.STATUS_CHOICES, default="applied")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # the deletion flash is not needed as on deletion of the user or the jobs 
    # all the application on that particular case will be gone
    is_deleted = models.BooleanField(default=False, null=True, editable=False)
    is_active = models.BooleanField(default=True, null=True)
