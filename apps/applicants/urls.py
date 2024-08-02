from django.urls import path

from apps.applicants.views import (
    AllApplicantsOfCompany,
    ApplyToJob,
    UpdateApplicationStatus, GetAppliedJobs,
    ApplicationStats
)

urlpatterns = [
    path("applicants/", AllApplicantsOfCompany.as_view(), name="applicants"),
    path("applied_jobs/",GetAppliedJobs.as_view(), name="applied_jobs"),
    path("apply/job", ApplyToJob.as_view(), name="applytojob"),
    path(
        "application/updatestatus",
        UpdateApplicationStatus.as_view(),
        name="updateapplicationstatus",
    ),
    path(
        "application/stats",
        ApplicationStats.as_view(),
        name="applicationstats"
    )
]
