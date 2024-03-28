from django.urls import path

from apps.applicants.views import AllApplicantsOfCompany, ApplyToJob, UpdateApplicationStatus

urlpatterns = [
    path("applicants/", AllApplicantsOfCompany.as_view(), name="applicants"),
    path("apply/job", ApplyToJob.as_view(), name="applytojob"),
    path("application/updatestatus", UpdateApplicationStatus.as_view(), name="updateapplicationstatus")
]
