from rest_framework import status, permissions, exceptions
from rest_framework.views import APIView
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema

from apps.applicants.models import Applicants
from apps.userprofile.models import UserProfile
from apps.jobs.models import Job
from apps.accounts.permissions import IsEmployer, IsJobSeeker, IsProfileCompleted
from apps.applicants.serializers import (
    ApplicantModelSerializer, 
    ApplyToJobSerializer, 
    UpdateApplicationStatusSerializer
)


class AllApplicantsOfCompany(APIView):
    """Fetch all applicant who have applied to this
    company ordered in the reverse time based order with their current state
    """
    permission_classes = [
        permissions.IsAuthenticated, 
        IsEmployer, 
        IsProfileCompleted
    ]

    @extend_schema(
        responses={200: ApplicantModelSerializer(many=True)},
        tags=["applications"]
    )
    def get(self, request):
        """List all users that belong to company"""
        applicants = Applicants.objects.filter(job__employer = request.user)

        return Response(
            ApplicantModelSerializer(applicants, many=True).data, 
            status=status.HTTP_200_OK
        )
    

class ApplyToJob(APIView):
    """Apply to a job"""
    permission_classes = [
        permissions.IsAuthenticated, 
        IsJobSeeker, 
        IsProfileCompleted
    ]

    @extend_schema(
        request=ApplyToJobSerializer,
        tags=["applications"]
    )
    def post(self, request):
        serializer = ApplyToJobSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)

        # fetching job and user profile to create an application
        user_profile = UserProfile.objects.get(user_id = request.user.id)
        try:
            job = Job.objects.get(job_id = serializer.data["job_id"])
        except Job.DoesNotExist:
            raise exceptions.NotFound()
        
        application = Applicants(job = job, user = user_profile)
        application.save()

        return Response(
            {"msg": "Created", "application_id": application.id},
            status = status.HTTP_201_CREATED
        )
        

class UpdateApplicationStatus(APIView):
    """Update application status of a applicant"""
    permission_classes = [
        permissions.IsAuthenticated,
        IsEmployer,
        IsProfileCompleted
    ]

    @extend_schema(
        request=UpdateApplicationStatusSerializer,
        tags=["applications"]
    )
    def post(self, request):
        serializer = UpdateApplicationStatusSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if not Applicants.objects.filter(
                id = serializer.data["application_id"]
            ).update(status = serializer.data["status"]):

            raise exceptions.NotFound()
        
        return Response(
            {"msg": "Success", "detail": "Status updated successfully."},
            status = status.HTTP_200_OK
        )
