from datetime import timedelta
import os
import uuid
from re import search
from typing import Any

from django.db.models import Count
import django.core.exceptions
from django.forms import ValidationError
from django.http import FileResponse, JsonResponse
from django.db.utils import IntegrityError
from django.core.paginator import Paginator, PageNotAnInteger, EmptyPage
from django.utils import datetime_safe, timezone
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.accounts.models import User as user_auth
from apps.accounts.views import Moderator
from apps.jobs.constants import response, values
from apps.jobs.models import Applicants, Company, ContactMessage, Job, User
from apps.jobs.serializers import (
    ApplicantsSerializer,
    CompanySerializer,
    ContactUsSerializer,
    JobSerializer,
    UserSerializer,
)
from apps.jobs.utils.validators import validationClass

from .utils.user_permissions import UserTypeCheck

# Create your views here.
# the ModelViewSet provides basic crud methods like create, update etc.

class JobViewSets(viewsets.ModelViewSet):
    """
    Job object viewsets
    API: /api/v1/jobs
    Database table name: tbl_job
    Functions:
        1. List jobs/specific job
        3. check number of applicants
        4. create or update job
    """

    queryset = Job.objects.all()
    serializer_class = JobSerializer

    # Defining filters
    # DjangoFilterBackend allows to use filters in the URL as well (like /api/?company="xyz")
    # SearchFilter means the same except it'll operate on N number of fields but in the url
    # it'll be like (/api/company/?search="xyz")
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["job_role", "location", "is_active"]

    @action(detail=False, methods=['get'])
    def public_jobs(self, request):
        """
        API: /public_jobs
        Return only 10-20 jobs
        """

        jobs_data = self.queryset.filter(is_created=True, is_deleted=False)
        serialized_jobs_data = JobSerializer(jobs_data, many=True)
        return response.create_response(
            serialized_jobs_data.data[0:2],
            status.HTTP_200_OK
        )
    
    def list(self, request):
        """
        Overrided the default list action provided by
        the ModelViewSet, in order to contain a new field
        called 'No of applicants' to the serializer data
        """

        # check for the query_params (in case of filter)
        filters_dict = {}
        if request.query_params:
            filters = request.query_params
            for filter_name, filter_value in filters.items():
                if filter_name in self.filterset_fields and filter_value:
                    filters_dict[filter_name] = filter_value

        # Even if the filters_dict is empty, it returns
        # overall data present in the Job, exception if wrong
        # uuid value is given.
        try:
            jobs_data = self.queryset.filter(
                **filters_dict, is_created=True, is_deleted=False
            )
        except django.core.exceptions.ValidationError as err:
            return response.create_response(err.messages, status.HTTP_404_NOT_FOUND)
        else:
            # Use Paginator for the queryset
            page_number = request.GET.get("page", 1)
            paginator = Paginator(jobs_data, values.ITEMS_PER_PAGE)  # 5 items per page

            try:
                jobs_data = paginator.page(page_number)
            except PageNotAnInteger:
                jobs_data = paginator.page(1)
            except EmptyPage:
                return response.create_response([], status.HTTP_200_OK)

            serialized_job_data = self.serializer_class(
                jobs_data, many=True, context={"request": request}
            )

            # get number of applicants
            if serialized_job_data:
                serialized_job_data = JobViewSets.get_number_of_applicants(
                    serialized_job_data
                )

            return response.create_response(
                serialized_job_data.data, status.HTTP_200_OK
            )

    def create(self, request, *args, **kwargs):
        """Overriding the create method to include permissions"""

        employer_id = request.user_id

        if not employer_id or not UserTypeCheck.is_user_employer(employer_id):
            return response.create_response(
                response.PERMISSION_DENIED
                + " You don't have permissions to create a job",
                status.HTTP_401_UNAUTHORIZED,
            )

        # Add employer_id to the request.data
        request.data["employer_id"] = employer_id

        return super().create(request, *args, **kwargs)

    @action(detail=False, methods=["get"], url_path="details")
    def details(self, request, *args, **kwargs):
        """
        API: /api/v1/jobs/details
        This method retrieves job data by job_id provided in the query parameter.
        """

        job_id = request.query_params.get("job_id")

        if not job_id or not validationClass.is_valid_uuid(job_id):
            return response.create_response(
                "Invalid or missing 'job_id' query parameter in the URL",
                status.HTTP_400_BAD_REQUEST
            )
        
        try:
            job_data = Job.objects.filter(job_id=job_id)
        except Job.DoesNotExist:
            return response.create_response(
                f"Job with job_id '{job_id}' does not exist", status.HTTP_404_NOT_FOUND
            )
        
        serialized_job_data = self.serializer_class(job_data, many=True)
        if serialized_job_data:
            serialized_job_data = JobViewSets.get_number_of_applicants(
                serialized_job_data
            )
        return response.create_response(serialized_job_data.data, status.HTTP_200_OK)

    @staticmethod
    def get_number_of_applicants(serialized_data):
        """
        return serialized_data with a new field added to it,
        that contains count of number of applicants.
        """

        if not serialized_data:
            raise Exception("Serialized data not provided")

        # check for "error" key in the serialized data
        # this is necessary because we don't have to display
        # number_of_applications in case of error message
        if not serialized_data.data or "error" in serialized_data.data[0]:
            return serialized_data

        for jobdata in serialized_data.data:
            job_id = jobdata.get(values.JOB_ID)
            number_of_applicants = Applicants.objects.filter(job_id=job_id).count()
            jobdata.update({"Number of Applicants": number_of_applicants})

        return serialized_data

    @staticmethod
    def get_active_jobs_count(serialized_company_data):
        """
        Add a new field called "Active Jobs" to the serialized data,
        that contains the count of active jobs present in the company.
        """

        for company in serialized_company_data.data:
            jobs_belong_to_company = Job.objects.filter(
                company_id=company.get("company_id")
            )
            active_jobs = sum(1 for job in jobs_belong_to_company if job.is_active and job.is_created)
            company.update({"Active Jobs": active_jobs})

        return serialized_company_data

    @action(detail=True, methods=["get"])
    def users(self, request, pk=None):
        """
        API Path: /api/v1/jobs/{pk}/users
        to find out how many users have applied for
        this job using job_id.
        """

        # check if pk's value is a valid UUID
        checkUUID = validationClass.is_valid_uuid(pk)
        if not checkUUID:
            return response.create_response(
                f"value {pk} isn't a correct id", status.HTTP_404_NOT_FOUND
            )

        # get the specific job or return 404 if not found
        try:
            jobdata = Job.objects.get(pk=pk)
        except Exception:
            return response.create_response(
                "Job doesn't exist", status.HTTP_404_NOT_FOUND
            )
        else:
            job_id = jobdata.job_id

            # get all the users object
            user_data = Applicants.objects.filter(job_id=job_id)
            serialized_data = ApplicantsSerializer(
                user_data, many=True, context={"request": request}
            )
            return response.create_response(serialized_data.data, status.HTTP_200_OK)

    @action(detail=True, methods=["post"])
    def apply(self, request, pk=None):
        """Apply job functionality implementation"""

        job_id = pk
        user_id = request.data[values.USER_ID]

        # validate, if both of them exists or not
        response_message = validationClass.validate_id(
            job_id, "job-id", Job
        ) and validationClass.validate_id(user_id, "user-id", User)
        if not response_message["status"]:
            return response.create_response(
                response_message["error"], status.HTTP_400_BAD_REQUEST
            )

        # Check whether the user has applied for the job before
        apply_job_status = Applicants.objects.filter(
            job_id=job_id, user_id=user_id
        ).exists()
        if apply_job_status:
            return response.create_response(
                "You have already applied for this Job", status.HTTP_200_OK
            )

        # Get the data from the user's database (only resume N cover_letter)
        # if any single one of them isn't found, return a message to update that.
        applyjob_data = (
            User.objects.filter(user_id=user_id)
            .values("resume", "cover_letter")
            .first()
        )

        for key, value in applyjob_data.items():
            if not value:
                return response.create_response(
                    f"You don't have {key} updated", status.HTTP_400_BAD_REQUEST
                )

        # Get the employer-id from the database
        # employer-id always exists in the db, without this job can't be created
        job_data = Job.objects.filter(job_id=job_id)
        if job_data.exists():
            employer_id = job_data.first()[values.EMPLOYER_ID]
        else:
            return response.create_response(
                f"Given job_id \'{job_id}\' does not exist",
                status.HTTP_404_NOT_FOUND
            )

        # Prepare the overall dictionary to save into the database
        # Add job-id, user-id, employer-id to the applyjob_data
        applyjob_data[values.JOB_ID] = job_id
        applyjob_data[values.USER_ID] = user_id
        applyjob_data[values.EMPLOYER_ID] = employer_id

        # Add this application into the database
        applyjob = Applicants(**applyjob_data)
        applyjob.save()

        return response.create_response(
            "You have successfully applied for this job",
            status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"], permission_classes=[UserTypeCheck])
    def update_application(self, request, pk=None):
        """This method updates the status of user application"""

        # check for status_id
        if "status" not in request.data or not request.data["status"]:
            return response.create_response(
                "status-id not present or invalid",
                status.HTTP_400_BAD_REQUEST,
            )

        # check if job_id is valid & present in db or not
        response_message = validationClass.validate_id(pk, "job-id", Job)
        if not response_message["status"]:
            return response.create_response(
                response_message["error"], status.HTTP_400_BAD_REQUEST
            )

        # check if the given employer_id has posted the job (given by job-id)
        employer_id = request.data[values.EMPLOYER_ID]
        job_employer_id = (
            Job.objects.filter(job_id=pk)
            .values(values.EMPLOYER_ID)
            .first()[values.EMPLOYER_ID]
        )
        if str(job_employer_id) != employer_id:
            return response.create_response(
                "This job isn't posted by the given employer id",
                status.HTTP_406_NOT_ACCEPTABLE,
            )

        # Update the status of current application
        try:
            Applicants.objects.filter(employer_id=employer_id).update(
                status=request.data["status"]
            )
        except Exception as err:
            return response.create_response(
                response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        else:
            return response.create_response(
                "Status has been updated!!", status.HTTP_200_OK
            )

    @action(detail=False, methods=["get"])
    def featured_jobs(self, request):
        """
        API: /user/featured_jobs/
        This method returns list of featured jobs based on
        Following conditions:
        1. Job posted within past 3 weeks till now
        2. Job.is_active is True
        3. Find out 6 jobs with maximum number of applicants
        """

        # past 3 weeks datetime specified for featured jobs (can be modified as per use)
        past_3_weeks_datetime = datetime_safe.datetime.now(tz=timezone.utc) - timedelta(
            values.PAST_3_WEEK_DATETIME_DAYS18
        )

        # get the jobs_data and sort it in DESC order
        # `-` with column name indicates to return the result in DESC order
        try:
            jobs_data = Job.objects.filter(
                created_at__gt=past_3_weeks_datetime, is_active=True
            ).order_by("-created_at")

            jobs_posted_within_3_weeks = JobSerializer(jobs_data, many=True)

            # find out how many jobs were posted within past_3_weeks
            jobs_posted_within_3_weeks = JobViewSets.get_number_of_applicants(
                jobs_posted_within_3_weeks
            )

            # find 5 jobs with maximum number of applicants
            featured_jobs = sorted(
                jobs_posted_within_3_weeks.data,
                key=lambda k: (k.get("Number of Applicants")),
                reverse=True,
            )

            return response.create_response(featured_jobs[0:10], status.HTTP_200_OK)
        except Exception:
            return response.create_response(
                response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def update(self, request, *args, **kwargs):
        """
        API: UPDATE /jobs/{id}
        Overriding update method to first check for
        Moderator and Employer user_type associated with the user, and
        then perform an update
        """

        # check if the user_id present in the request belongs to Employer or Moderator
        if not (
            UserTypeCheck.is_user_employer(request.user_id)
            or Moderator().has_permission(request)
        ):
            return response.create_response(
                response.PERMISSION_DENIED
                + " You don't have permissions to update a job",
                status.HTTP_401_UNAUTHORIZED,
            )

        return super().update(request, *args, **kwargs)

    def destroy(self, request, pk, *args, **kwargs):
        """
        API: DELETE /jobs/{id}
        Overriding destroy method to first check for
        Moderator and Employer associated with the user, and
        then perform an update.
        """

        # check if the user_id present in the request belongs to Employer or Moderator
        if not (
            UserTypeCheck.is_user_employer(request.user_id)
            or Moderator().has_permission(request)
        ):
            return response.create_response(
                response.PERMISSION_DENIED
                + " You don't have permissions to delete a job",
                status.HTTP_401_UNAUTHORIZED,
            )

        # check if the job is already deleted or not
        if validationClass.is_valid_uuid(pk):
            job = Job.objects.filter(job_id=pk, is_created=False, is_deleted=True)
            if job.exists():
                return response.create_response(
                    "Given job_id does not exist or already deleted",
                    status.HTTP_404_NOT_FOUND,
                )
        else:
            return response.create_response(
                "Job id is not valid",
                status.HTTP_400_BAD_REQUEST
            )
        # if user is employer don't remove the job from the db table
        # else, set is_created=False and is_deleted=True
        if UserTypeCheck.is_user_employer(request.user_id):
            try:
                updated_job_data = Job.objects.filter(job_id=pk)
                updated_job_data.update(is_created=False, is_deleted=True, is_active=False)
                serialized_updated_job_data = JobSerializer(updated_job_data, many=True)
                return response.create_response(
                    serialized_updated_job_data.data, status.HTTP_200_OK
                )
            except Exception:
                return response.create_response(
                    response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        return super().destroy(request, *args, **kwargs)

    @action(detail=False, methods=["get"])
    def get_posted_jobs(self, request):
        """
        API: localhost:8000/jobs/get_posted_jobs/
        This method returns a list of jobs where is_posted is True.
        """

        # Get only posted jobs
        posted_jobs_data = Job.objects.filter(posted=True)
        page_number = request.GET.get("page", 1)  # used paginator for queryset
        paginator = Paginator(
            posted_jobs_data, values.ITEMS_PER_PAGE
        )  # per page 2 items

        try:
            posted_jobs_data = paginator.page(page_number)
        except PageNotAnInteger:
            posted_jobs_data = paginator.page(1)
        except EmptyPage:
            return response.create_response([], status.HTTP_200_OK)

        serialized_posted_jobs_data = self.serializer_class(
            posted_jobs_data, many=True, context={"request": request}
        )

        # Add number of applicants to the serialized data
        if serialized_posted_jobs_data:
            serialized_posted_jobs_data = JobViewSets.get_number_of_applicants(
                serialized_posted_jobs_data
            )
            return response.create_response(
                serialized_posted_jobs_data.data, status.HTTP_200_OK
            )

    @action(detail=False, methods=["get"])
    def get_jobs(self, request):
        """
        API: /api/v1/jobs/get_jobs/
        This method retrieves jobs based on dynamic filters such as
        category, job type, experience, and qualification provided in the query parameters.
        It also includes the count of active jobs for each filter.
        """

        # Extract filters from query parameters
        filters = {}
        category = request.query_params.get("category", None)
        job_type = request.query_params.get("job_type", None)
        experience = request.query_params.get("experience", None)

        if category:
            filters["category"] = category
        if job_type:
            filters["job_type"] = job_type
        if experience:
            filters["experience__lte"] = int(
                experience
            )  # Filter jobs with experience greater than or equal to specified value

        # Get the filtered jobs
        filtered_jobs_data = Job.objects.filter(**filters, is_active=True)

        # If no jobs match the filters, return a specific response
        if not filtered_jobs_data.exists():
            return response.create_response(
                "Sorry, currently no jobs available as per your request",
                status.HTTP_200_OK,
            )

        # Serialize the filtered job data
        serialized_filtered_jobs_data = JobSerializer(
            filtered_jobs_data, many=True
        ).data

        return response.create_response(
            serialized_filtered_jobs_data, status.HTTP_200_OK
        )
    
    @action(detail=False, methods=['get'])
    def get_jobs_categories(self, request):
        """
        API: /get_jobs_categories
        Return open positions present in specific job category
        """
        
        try:
            job_data = self.queryset.filter(is_created=True, is_deleted=False)
            
            if job_data.exists():
                category_counts = {}

                for job in job_data:
                    category = job.category.lower().strip()
                    category_counts[category] = category_counts.get(category, 0) + 1
                
                open_positions_in_category = []

                for category, count in category_counts.items():
                    open_positions_in_category.append(
                        {
                            "id": len(open_positions_in_category)+1, 
                            "category": category, 
                            "open_position": count
                        }
                    )

                return response.create_response(
                    open_positions_in_category,
                    status.HTTP_200_OK
                )

            return response.create_response(
                "No jobs are present right now",
                status.HTTP_200_OK
            )

        except Exception:
            return response.create_response(
                response.SOMETHING_WENT_WRONG,
                status.HTTP_400_BAD_REQUEST
            )


class UserViewSets(viewsets.ModelViewSet):
    """
    User object viewsets
    API: /api/v1/user
    Database: tbl_user_profile
    Functions:
        1. create or update user
        2. list users/specific user
        3. check jobs applied by a specific user
    """

    queryset = User.objects.all()
    serializer_class = UserSerializer

    def update(self, request, *args, **kwargs):
        """
        Overriding the update method (used in PUT request),
        This method updates an existing user profile in the database.

        NOTE: tbl_user_auth has "id", tbl_user_profile has "user_id" as primary key.
        """

        # Perform check on data with PUT Request
        if not request.data:
            return response.create_response(
                response.REQUEST_BODY_NOT_PRESENT, status.HTTP_400_BAD_REQUEST
            )

        validator = validationClass()

        if request.FILES:
            # resume validation
            resume_data = request.FILES.get("resume")
            if resume_data:
                validation_result = validator.resume_validation(resume_data)
                if not validation_result[0]:
                    return Response(
                        {"message": validation_result[1]},
                        status=status.HTTP_406_NOT_ACCEPTABLE,
                    )

            # image validation
            image_data = request.FILES.get("profile_picture")
            if image_data:
                validation_result = validator.image_validation(image_data)
                if not validation_result[0]:
                    return Response(
                        {"message": validation_result[1]},
                        status=status.HTTP_406_NOT_ACCEPTABLE,
                    )

        # Get the user-id from access-token, and update will be performed
        # only on the user-id present in access-token, not the one we get from
        # the API endpoint.

        user_id = request.user_id

        # get data from the request
        user_data = request.data

        # validate some data first
        try:
            validationClass.validate_fields(user_data)

        except Exception as err:
            return response.create_response(err.__str__(), status.HTTP_400_BAD_REQUEST)

        try:
            # update in the tbl_user_profile
            User.objects.filter(user_id=user_id).update(**user_data)

            # update in the tbl_user_auth (only - user_name, user_email, user_type)
            tbl_user_auth_data = {
                key: user_data[key]
                for key in ("name", "email", "user_type")
                if key in user_data
            }
            user_auth.objects.filter(id=user_id).update(**tbl_user_auth_data)
        except IntegrityError:
            return response.create_response(
                "You've supplied either improper values or same values to update, Use a different one",
                status.HTTP_401_UNAUTHORIZED,
            )
        except Exception as err:
            print("Exception occurred while updating the user data in the db table")
            return response.create_response(
                f"{response.SOMETHING_WENT_WRONG}",
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        else:
            user_data = User.objects.get(user_id=user_id)
            return response.create_response(
                UserSerializer(user_data).data, status.HTTP_200_OK
            )

    @action(detail=False, methods=["get"])
    def get_profile_details(self, request):
        """
        API: /api/v1/user/myProfile
        Returns user profile data in the response based on
        user_id present in the AccessToken
        """

        try:
            user_id = request.user_id

            # get user data
            user_data = self.queryset.filter(user_id=user_id)
            serialized_user_data = self.serializer_class(user_data, many=True)
            return response.create_response(
                serialized_user_data.data, status.HTTP_200_OK
            )
        except Exception:
            return response.create_response(
                response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=["get"])
    def jobs(self, request):
        """
        API: /api/v1/user/jobs/
        This method finds out how many jobs a person has applied so far,
        """

        try:
            user_id = request.user_id
            jobs_data = None
            # get the applications submmited by this user
            applications = Applicants.objects.filter(user_id=user_id).values(values.JOB_ID)
            if applications.exists():
                # get the job_ids
                applications_count = applications.count()
                jobs_id = [
                    applications[n][values.JOB_ID] for n in range(0, applications_count)
                ]

                # get the jobs data
                jobs_data = Job.objects.filter(job_id__in=jobs_id)
                # here we serialize the data, for comm.
                serialized_jobs_data = JobSerializer(
                    jobs_data, many=True, context={"request": request}
                )
                serialized_jobs_data = self.get_application_status(serialized_jobs_data)
                return response.create_response(
                    serialized_jobs_data.data, status.HTTP_200_OK
                )
            else:
                return response.create_response(
                    "You haven't applied to any job", status.HTTP_200_OK
                )
        except Exception:
            return response.create_response(
                response.SOMETHING_WENT_WRONG, 
                status.HTTP_404_NOT_FOUND
            )

    @action(detail=False, methods=["delete"])
    def delete_user(self, request):
        """
        API: /delete_user/
        This method deletes a user from the tbl_user_profile and tbl_user_profile,
        However this endpoint should be called only when the user provide proper
        authentication details before proceeding further.
        """

        user_id = request.user_id

        try:
            # check if the given user_id exists or not
            user_object = User.objects.filter(user_id=user_id)
            # remove user details from tbl_user_profile
            user_object.delete()
            # remove user details from tbl_user_auth
            user_auth.objects.filter(id=user_id).delete()
            return response.create_response(
                "User Profile Deleted Successfully", status_code=status.HTTP_200_OK
            )
        except Exception as err:
            return response.create_response(
                response.SOMETHING_WENT_WRONG + err.__str__(),
                status_code=status.HTTP_404_NOT_FOUND,
            )

    def get_application_status(self, serialized_data):
        if not serialized_data:
            raise Exception("Serialized Data not provided")

        for job_data in serialized_data.data:
            job_id = job_data.get(values.JOB_ID)
            user_application = Applicants.objects.filter(job_id=job_id)
            if user_application.exists():
                status = user_application.first().status
                job_data.update({"status": status})

        return serialized_data

    @action(detail=True, methods=["put"])
    def reupload_documents(self, request, pk=None):
        """
        API: /api/v1/user/{pk}/reupload-documents
        Allows users to re-upload their documents (resume, profile picture, cover letter).
        """
        user = User.objects.get(user_id=pk)
        if not user:
            return response.create_response(
                "User does not exist", status.HTTP_404_NOT_FOUND
            )

        # Resume re-upload
        resume_data = request.FILES.get("resume")
        if resume_data:
            # Delete the previous resume if it exists
            if user.resume:
                user.resume.delete()
            user.resume = resume_data
            user.save()

        # Profile Picture re-upload
        profile_picture_data = request.FILES.get("profile_picture")
        if profile_picture_data:
            # Delete the previous profile picture if it exists
            if user.profile_picture:
                user.profile_picture.delete()
            user.profile_picture = profile_picture_data
            user.save()

        # Cover Letter re-upload
        cover_letter_data = request.FILES.get("cover_letter")
        if cover_letter_data:
            # Delete the previous cover letter if it exists
            if user.cover_letter:
                user.cover_letter.delete()
            user.cover_letter = cover_letter_data
            user.save()

        return response.create_response(
            "Documents re-uploaded successfully", status.HTTP_200_OK
        )

    @action(detail=True, methods=["get"])
    def download_documents(self, request, pk=None):
        """
        API: /api/v1/user/{pk}/download-documents
        Allows users to download their documents (resume, profile picture, cover letter).
        """
        user = User.objects.get(user_id=pk)
        if not user:
            return response.create_response(
                "User does not exist", status.HTTP_404_NOT_FOUND
            )

        document_type = request.query_params.get("document_type", "")
        file_path = None

        # Determine the file path based on the requested document type
        if document_type == values.RESUME_DOCUMENT_TYPE:
            file_path = user.resume.path
        elif document_type == values.PROFILE_PICTURE_DOCUMENT_TYPE:
            file_path = user.profile_picture.path
        elif document_type == values.COVER_LETTER_DOCUMENT_TYPE:
            file_path = user.cover_letter.path

        if not file_path or not os.path.exists(file_path):
            return response.create_response(
                f"{document_type.capitalize()} not found", status.HTTP_404_NOT_FOUND
            )

        # Serve the file using Django FileResponse
        return FileResponse(open(file_path, "rb"), as_attachment=True)
    
    @action(detail=False, methods=["post"])
    def retrieve_users(self, request):
        """
        to retrive user as per the filters in the post body.
        """

        data = request.data
        qualification = data.get("qualification", None)
        experience = data.get("experience", None)
        address = data.get("address", None)

        queryset = User.objects.all()

        if qualification:
            queryset = queryset.filter(qualification__icontains=qualification)

        if experience is not None:
            queryset = queryset.filter(experience=experience)

        if address:
            queryset = queryset.filter(address__icontains=address)

        serialized_data = UserSerializer(queryset, many=True)
        return Response(serialized_data.data, status=status.HTTP_200_OK)

class CompanyViewSets(viewsets.ModelViewSet):
    """
    Company object viewsets
    API: /api/v/company
    Database: tbl_company
    Functions:
        1. create or update functions
        2. get jobs available in a company
        3. get user available in a company
        4. list companies/specific company
    """

    queryset = Company.objects.all()
    serializer_class = CompanySerializer

    # Basic filters
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["name", "location"]

    def list(self, request):
        """
        Method to return a list of companies available,
        Along with the count of active jobs present in the company
        """

        try:

            company_data = self.queryset.filter(is_created=True, is_deleted=False)
            serialized_company_data = self.serializer_class(
                company_data, many=True, context={"request": request}
            )

            # get number of applicants
            if serialized_company_data:
                serialized_company_data = JobViewSets.get_active_jobs_count(
                    serialized_company_data
                )

            return response.create_response(
                serialized_company_data.data, status.HTTP_200_OK
            )
        except Exception:
            return response.create_response(
                response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def retrieve(self, request, pk=None):
        """
        retrieve the data of given company id
        """

        if not validationClass.is_valid_uuid(pk):
            return response.create_response(
                f"value {pk} isn't a correct id",
                status.HTTP_404_NOT_FOUND,
            )

        try:
            # filter based on pk
            company_data = Company.objects.filter(company_id=pk, is_created=True, is_deleted=False)
            serialized_company_data = self.serializer_class(company_data, many=True)
            if serialized_company_data:
                serialized_company_data = JobViewSets.get_active_jobs_count(
                    serialized_company_data
                )
            return response.create_response(
                serialized_company_data.data, status.HTTP_200_OK
            )
        except Exception:
            return response.create_response(
                response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def update(self, request, *args, **kwargs):
        """
        API: UPDATE /company/{id}
        Overriding update method to first check for
        Moderator and Employer user_type associated with the user, and
        then perform an update
        """

        # check if the user_id present in the request belongs to Employer or Moderator
        if not (
            UserTypeCheck.is_user_employer(request.user_id)
            or Moderator().has_permission(request)
        ):
            return response.create_response(
                response.PERMISSION_DENIED
                + " You don't have permissions to update company details",
                status.HTTP_401_UNAUTHORIZED,
            )

        return super().update(request, *args, **kwargs)

    def destroy(self, request, pk=None, *args, **kwargs):
        """
        API: DELETE /company/{id}
        Overriding destroy method to first check for
        Moderator and Employer associated with the user, and
        then perform an update.
        """

        # check if the user_id present in the request belongs to Employer or Moderator
        if not (
            UserTypeCheck.is_user_employer(request.user_id)
            or Moderator().has_permission(request)
        ):
            return response.create_response(
                response.PERMISSION_DENIED
                + " You don't have permissions to delete a company",
                status.HTTP_401_UNAUTHORIZED,
            )

        # check if the job is already deleted or not
        company_data = Company.objects.filter(
            company_id=pk, is_created=False, is_deleted=True
        )
        if company_data.exists():
            return response.create_response(
                "Given company_id does not exist or already deleted",
                status.HTTP_404_NOT_FOUND,
            )

        # if user is employer don't remove the company from the db table
        # else, set is_created=False and is_deleted=True
        if UserTypeCheck.is_user_employer(request.user_id):
            try:
                company_data = Company.objects.filter(company_id=pk)
                company_data.update(is_created=False, is_deleted=True)
                serialized_company_data = CompanySerializer(company_data, many=True)
                return response.create_response(
                    serialized_company_data.data, status.HTTP_200_OK
                )
            except Exception:
                return response.create_response(
                    response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
                )

        return super().destroy(request, *args, **kwargs)

    @action(detail=False, methods=["get"])
    def jobs(self, request):
        """
        Method to get a list of jobs
        """

        queryset_data = self.get_queryset().filter(is_created=True, is_deleted=False)
        serialized_company_data = self.serializer_class(queryset_data, many=True)
        for company_data in serialized_company_data.data:
            company_id = company_data.get(values.COMPANY_ID)

            # get jobs data by company_id from database
            # .values() returns the QuerySet
            # jobData = Job.objects.filter(company=companyId).values()
            job_data = Job.objects.filter(company_id=company_id, is_created=True, is_deleted=False)
            company_data.update({"Jobs": job_data.values()})

        return response.create_response(
            serialized_company_data.data, status.HTTP_200_OK
        )

    @action(detail=False, methods=["get"])
    def users(self, request):
        """
        Method to get the list of users
        """

        queryset_data = self.get_queryset().filter(is_created=True, is_deleted=False)
        serialized_company_data = self.serializer_class(queryset_data, many=True)
        for company_data in serialized_company_data.data:
            company_id = company_data.get(values.COMPANY_ID)

            # Get user information by company_id from database
            user_data = User.objects.filter(company_id=company_id).values()
            company_data.update({"User": user_data})

        return response.create_response(
            serialized_company_data.data, status.HTTP_200_OK
        )


class ContactUsViewSet(viewsets.ModelViewSet):
    """Company object viewsets
    API: /api/v/contact-us
    Database: tb1_contact_us
    Functions:
        1. take input from user end
        2. create contact message
        3. contact message stored in database
    """

    # queryset = ContactMessage.objects.all()
    serializer_class = ContactUsSerializer
    http_method_names = ["post"]

    def get_queryset(self):
        return ContactMessage.objects.all()

    @action(detail=False, methods=["post"])
    def create_contact_message(self, request):
        full_name = request.data.get("full_name")
        email = request.data.get("email")
        message = request.data.get("message")

        validation_error = validationClass.validate_fields(
            {"full_name": full_name, "email": email, "message": message}
        )

        if validation_error:
            return Response(validation_error, status=status.HTTP_400_BAD_REQUEST)

        serializer_class = ContactUsSerializer(data=request.data)
        if serializer_class.is_valid():
            serializer_class.save()
            return Response(serializer_class.data, status=status.HTTP_200_OK)
        else:
            return Response(serializer_class.errors, status=status.HTTP_400_BAD_REQUEST)

    def list(self, request, *args, **kwargs):
        if request.method == "GET":
            if UserTypeCheck.is_user_employer:
                return Response(
                    {"Access forbidden for non-moderator user"},
                    status=status.HTTP_403_FORBIDDEN,
                )
            else:
                return super().list(request, *args, **kwargs)
        else:
            return super().list(request, *args, **kwargs)


class ModeratorViewSet(viewsets.ViewSet):
    """
    API: /api/v1/moderator-actions/
    Functions:
        1. list pending items (jobs or companies)
        2. approve pending items (jobs or companies)
        3. reject pending items (jobs or companies)
    """

    def __init__(self, **kwargs: Any) -> None:
        self.objects = ["company", "job"]
        super().__init__(**kwargs)
        self._type = ""

    @action(detail=False, methods=["post"], permission_classes=[Moderator])
    def list_pending_items(self, request):
        """
        API: /list_pending_items/
        Method to list unapproved jobs and companies
        """

        if response_value := self.validate_request_data(request):
            return response_value

        if self._type == "job":
            return response.create_response(
                self.list_pending_objects(request, Job, JobSerializer), status.HTTP_200_OK
            )
        elif self._type == "company":
            return response.create_response(
                self.list_pending_objects(request, Company, CompanySerializer), status.HTTP_200_OK
            )

    @action(detail=False, methods=["post"], permission_classes=[Moderator])
    def approve_pending_items(self, request):
        """
        API: /approve_pending_items/
        Method to set is_created=True for given object
        """

        if response_value := self.validate_request_data(request):
            return response_value

        if self._type == "job":
            return response.create_response(
                self.approve_pending_objects(request, Job, "job"), status.HTTP_200_OK
            )
        elif self._type == "company":
            return response.create_response(
                self.approve_pending_objects(request, Company, "company"), status.HTTP_200_OK
            )

    @action(detail=False, methods=["post"], permission_classes=[Moderator])
    def delete_pending_items(self, request):
        """
        API: /delete_pending_items/
        Method to remove records for the specific objects from
        the database
        """

        if response_value := self.validate_request_data(request):
            return response_value

        if self._type == "job":
            return response.create_response(
                self.remove_pending_objects(request, Job, "job"), status.HTTP_200_OK
            )
        elif self._type == "company":
            return response.create_response(
                self.remove_pending_objects(request, Company, "company"), status.HTTP_200_OK
            )

    def validate_request_data(self, request):
        """Method to perform checks on request.data"""

        if not request.data.get("type", None):
            return response.create_response(
                "'type' not provided", status.HTTP_400_BAD_REQUEST
            )

        type = request.data.get("type").lower()
        if type not in self.objects:
            return response.create_response(
                "wrong 'type' value specified", status.HTTP_404_NOT_FOUND
            )
        
        self._type = type

    def list_pending_objects(self, request, model, serializer):
        """
        Method to list all the items that are yet to be approved
        objects: Job and Company
        """

        try:
            pending_objects = model.objects.filter(is_created=False)
            pending_objects = serializer(pending_objects, many=True)
            return pending_objects.data
        except Exception:
            return response.SOMETHING_WENT_WRONG

    def approve_pending_objects(self, request, model, object_type):
        """
        Endpoint where a moderator can approve pending jobs
        created by employer
        """

        # check if the request body contains object_id
        object_id = object_type.lower()
        if object_type == "job":
            object_id = "job_id"
        elif object_type == "company":
            object_id = "company_id"

        if object_id := request.data.get(object_id, None):
            try:
                # check if the given object_id belongs to the object_type
                object_data = model.objects.filter(**{object_type:object_id}).values("is_created")
                if object_data and not object_data[0]["is_created"]:
                    object_data.update(is_created=True, is_deleted=False)
                    return f"{object_type} with id {object_id} has been approved successfully!!"
                return f"No pending {object_type} associated with the given {object_id} exist"
            except Exception:
                return response.SOMETHING_WENT_WRONG
        return f"\'{object_id}\' not provided"

    def remove_pending_objects(self, request, model, object_type):
        """
        Endpoint where a moderator can delete jobs deleted by employer
        This removes the jobs details from db as well.
        """

        object_type = object_type.lower()
        if object_type == "job":
            object_id = "job_id"
        elif object_type == "company":
            object_id = "company_id"
        
        # check if the request body contains job_id
        if object_id := request.data.get(object_id, None):
            try:
                # check if the given job_id belongs to the job object
                object_data = model.objects.filter(**{object_type:object_id})
                if object_data and object_data[0].is_deleted:
                    object_data.delete()
                    return f"{object_type} with id {object_id} has been deleted successfully!!"
                return f"No pending {object_type} associated with the given {object_id} exist"
            except Exception:
                return response.SOMETHING_WENT_WRONG
        return f"'{object_id}' not provided"
