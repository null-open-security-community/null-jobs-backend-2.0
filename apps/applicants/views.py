from drf_spectacular.utils import extend_schema
from rest_framework import exceptions, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.db.models import Count, Q

from apps.accounts.permissions import IsEmployer, IsJobSeeker, IsProfileCompleted
from apps.applicants.models import Applicants
from apps.applicants.serializers import (
    ApplicantModelSerializer,
    ApplyToJobSerializer,
    UpdateApplicationStatusSerializer, AppliedJobSerializer,
    ApplicationStatsResponseSerializer
)
from apps.jobs.models import Job
from apps.userprofile.models import UserProfile
from apps.utils.responses import InternalServerError


class AllApplicantsOfCompany(APIView):
    """Fetch all applicant who have applied to this
    company ordered in the reverse time based order with their current state
    """

    permission_classes = [permissions.IsAuthenticated, IsEmployer, IsProfileCompleted]

    @extend_schema(
        responses={200: ApplicantModelSerializer(many=True)}, tags=["applications"]
    )
    def get(self, request):
        """List all users that belong to company"""
        applicants = Applicants.objects.filter(job__employer=request.user)

        return Response(
            ApplicantModelSerializer(applicants, many=True).data,
            status=status.HTTP_200_OK,
        )


class ApplyToJob(APIView):
    """Apply to a job"""

    permission_classes = [permissions.IsAuthenticated, IsJobSeeker, IsProfileCompleted]

    @extend_schema(request=ApplyToJobSerializer, tags=["applications"])
    def post(self, request):
        serializer = ApplyToJobSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # fetching job and user profile to create an application
        user_profile = UserProfile.objects.get(user_id=request.user.id)
        try:
            job = Job.objects.get(job_id=serializer.data["job_id"])
        except Job.DoesNotExist:
            raise exceptions.NotFound()
        
        application = Applicants.objects.filter(job=job, user=user_profile)
        if application.exists():
            return Response(
                {"msg": "Already Applied!"},
                status=status.HTTP_403_FORBIDDEN
            )

        application = Applicants(job=job, user=user_profile)
        application.save()

        return Response(
            {"msg": "Created", "application_id": application.id},
            status=status.HTTP_201_CREATED,
        )


class UpdateApplicationStatus(APIView):
    """Update application status of a applicant"""

    permission_classes = [permissions.IsAuthenticated, IsEmployer, IsProfileCompleted]

    @extend_schema(request=UpdateApplicationStatusSerializer, tags=["applications"])
    def post(self, request):
        serializer = UpdateApplicationStatusSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        if not Applicants.objects.filter(id=serializer.data["application_id"]).update(
                status=serializer.data["status"]
        ):
            raise exceptions.NotFound()

        return Response(
            {"msg": "Success", "detail": "Status updated successfully."},
            status=status.HTTP_200_OK,
        )


class GetAppliedJobs(APIView):
    """
    get applied jobs will return all the applied jobs associated with that candidate
    """
    permission_classes = [permissions.IsAuthenticated, IsProfileCompleted]

    @extend_schema(
        responses={200: ApplicantModelSerializer(many=True)},
        tags=["applied_jobs"]
    )
    def get(self, request):
        """List all users that belong to the company, or a specific applicant by ID"""
        job_id = request.query_params.get('job_id')

        # finding out the user_id associated with logged in user_id
        user_id = UserProfile.objects.get(user_id=request.user.id)

        if job_id:
            try:
                applicant = Applicants.objects.get(user_id=user_id, job_id=job_id)
                return Response(
                    AppliedJobSerializer(applicant).data,
                    status=status.HTTP_200_OK
                )
            except Applicants.DoesNotExist:
                return Response(
                    {"detail": "Applicant not found."},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            applicants = Applicants.objects.filter(user_id=user_id).order_by('-created_at')
            return Response(
                AppliedJobSerializer(applicants, many=True).data,
                status=status.HTTP_200_OK
            )


class ApplicationStats(APIView):

    permission_classes = [permissions.IsAuthenticated, IsJobSeeker]

    @extend_schema(responses={200: ApplicationStatsResponseSerializer}, tags=["applications"])
    def get(self, request):
        try:
            userprofile = UserProfile.objects.get(user=request.user)
            counts = Applicants.objects.filter(user=userprofile).aggregate(
                applied_jobs=Count('id'),
                recruiter_actions=Count('id', filter=~Q(status='applied')),
                shortlisted_jobs=Count('id', filter=Q(status='shortlisted'))
            )

            return Response(ApplicationStatsResponseSerializer(counts).data, status=status.HTTP_200_OK)
        except Exception as e:
            raise InternalServerError()
    