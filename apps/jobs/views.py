import uuid
from re import search
import logging
import traceback
import django.core.exceptions
import jwt
from django.db.models.expressions import RawSQL
from django.db.utils import IntegrityError
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from pythonjsonlogger import jsonlogger
from apps.accounts.models import User as user_auth
from apps.jobs.constants import response, values
from apps.jobs.models import Applicants, Company, Job, User
from apps.jobs.serializers import (
    ApplicantsSerializer,
    CompanySerializer,
    JobSerializer,
    UserSerializer,
    ContactUsSerializer,
)
from apps.jobs.utils.validators import validationClass

from .utils.user_permissions import UserTypeCheck

# Create your views here.
# the ModelViewSet provides basic crud methods like create, update etc.

logger = logging.getLogger("jobs")


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
    filterset_fields = ["job_role", "location"]

    logger = logging.getLogger("jobs.JobViewSets")  # class specific self.logger

    def list(self, request):
        """
        Overrided the default list action provided by
        the ModelViewSet, in order to contain a new field
        called 'No of applicants' to the serializer data
        """
        try:
            request_id = getattr(request, "request_id", "N/A")
            self.logger.info("Listing jobs", extra={"request_id": request_id})

            filters_dict = {}
            if request.query_params:
                filters = request.query_params
                for filter_name, filter_value in filters.items():
                    if filter_name in self.filterset_fields and filter_value:
                        filters_dict[filter_name] = filter_value

            jobs_data = self.queryset.filter(**filters_dict)
            serialized_job_data = self.serializer_class(
                jobs_data, many=True, context={"request": request}
            )

            if serialized_job_data:
                serialized_job_data = self.get_number_of_applicants(serialized_job_data)

            return response.create_response(
                serialized_job_data.data, status.HTTP_200_OK
            )

        except Exception as e:
            self.logger.error(
                f"Error listing jobs: {e}", extra={"request_id": request_id}
            )
            self.logger.error(traceback.format_exc())
            return response.create_response(
                response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def create(self, request, *args, **kwargs):
        """Overriding the create method to include permissions"""
        try:
            request_id = getattr(request, "request_id", "N/A")
            employer_id = request.data.get(values.EMPLOYER_ID)
            self.logger.info(
                "Creating or updating job", extra={"request_id": request_id}
            )

            if not employer_id or not UserTypeCheck.is_user_employer(
                request.data[values.EMPLOYER_ID]
            ):
                self.logger.warning(
                    "Job Creation permission denied", extra={"request_id": request_id}
                )
                return response.create_response(
                    response.PERMISSION_DENIED
                    + " You don't have permissions to create jobs",
                    status.HTTP_401_UNAUTHORIZED,
                )

            return super().create(request, *args, **kwargs)

        except Exception as e:
            self.logger.error(
                f"Error creating or updating job: {e}", extra={"request_id": request_id}
            )
            self.logger.error(traceback.format_exc())
            return response.create_response(
                response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def retrieve(self, request, pk=None):
        """
        retrieve the data of given job id
        """
        try:
            request_id = getattr(request, "request_id", "N/A")
            self.logger.info(
                f"Retrieving job with ID: {pk}", extra={"request_id": request_id}
            )
            if not validationClass.is_valid_uuid(pk):
                self.logger.warning(
                    f"The id is not correct: {pk}", extra={"request_id": request_id}
                )
                return response.create_response(
                    f"value {pk} isn't a correct id",
                    status.HTTP_404_NOT_FOUND,
                )

            # filter based on pk
            job_data = Job.objects.filter(job_id=pk)
            serialized_job_data = self.serializer_class(job_data, many=True)
            if serialized_job_data:
                serialized_job_data = self.get_number_of_applicants(serialized_job_data)
            return response.create_response(
                serialized_job_data.data, status.HTTP_200_OK
            )

        except Exception as e:
            self.logger.error(
                f"Error retrieving job: {e}", extra={"request_id": request_id}
            )
            self.logger.error(traceback.format_exc())
            return response.create_response(
                response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get_number_of_applicants(self, serialized_data):
        """
        return serialized_data with a new field added to it,
        that contains count of number of applicants.
        """

        try:
            request_id = getattr(self.request, "request_id", "N/A")
            self.logger.info(
                "Getting number of applicants", extra={"request_id": request_id}
            )

            if not serialized_data:
                self.logger.warning(
                    "Serialized data not provided", extra={"request_id": request_id}
                )
                raise Exception("Serialized data not provided")

            if not serialized_data.data or "error" in serialized_data.data[0]:
                return serialized_data

            for jobdata in serialized_data.data:
                job_id = jobdata.get(values.JOB_ID)
                number_of_applicants = Applicants.objects.filter(job_id=job_id).count()
                jobdata.update({"Number of Applicants": number_of_applicants})

            return serialized_data

        except Exception as e:
            self.logger.error(
                f"Error getting number of applicants: {e}",
                extra={"request_id": request_id},
            )
            self.logger.error(traceback.format_exc())
            raise  # Re-raise the exception

    @action(detail=True, methods=["get"])
    def users(request, pk=None):
        """
        API Path: /api/v1/jobs/{pk}/users
        to find out how many users have applied for
        this job using job_id.
        """

        try:
            request_id = getattr(request, "request_id", "N/A")
            logger.info(
                f"Getting users for job with ID: {pk}", extra={"request_id": request_id}
            )

            checkUUID = validationClass.is_valid_uuid(pk)
            if not checkUUID:
                logger.warning(
                    f"value {pk} isn't a correct id", extra={"request_id": request_id}
                )
                return response.create_response(
                    f"value {pk} isn't a correct id", status.HTTP_404_NOT_FOUND
                )

            jobdata = Job.objects.get(pk=pk)
            job_id = jobdata.job_id
            user_data = Applicants.objects.filter(job_id=job_id)
            serialized_data = ApplicantsSerializer(
                user_data, many=True, context={"request": request}
            )

            return response.create_response(serialized_data.data, status.HTTP_200_OK)

        except Exception as e:
            logger.error(
                f"Error getting users for job: {e}", extra={"request_id": request_id}
            )
            logger.error(traceback.format_exc())
            return response.create_response(
                response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=["post"])
    def apply(request, pk=None):
        """Apply job functionality implementation"""

        try:
            request_id = getattr(request, "request_id", "N/A")
            logger.info(
                f"Applying for job with ID: {pk}", extra={"request_id": request_id}
            )

            job_id = pk
            user_id = request.data[values.USER_ID]

            response_message = validationClass.validate_id(
                job_id, "job-id", Job
            ) or validationClass.validate_id(user_id, "user-id", User)
            if response_message:
                return response.create_response(
                    response_message, status.HTTP_400_BAD_REQUEST
                )

            apply_job_status = Applicants.objects.filter(
                job_id=job_id, user_id=user_id
            ).exists()
            if apply_job_status:
                return response.create_response(
                    "You have already applied for this Job", status.HTTP_200_OK
                )

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

            employer_id = (
                Job.objects.filter(job_id=job_id)
                .values(values.EMPLOYER_ID)
                .first()[values.EMPLOYER_ID]
            )

            applyjob_data[values.JOB_ID] = job_id
            applyjob_data[values.USER_ID] = user_id
            applyjob_data[values.EMPLOYER_ID] = employer_id

            applyjob = Applicants(**applyjob_data)
            applyjob.save()
            logger.info("Job applied successfull", extra={"request_id": request_id})
            return response.create_response(
                "You have successfully applied for this job",
                status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(
                f"Error applying for job: {e}", extra={"request_id": request_id}
            )
            logger.error(traceback.format_exc())
            return response.create_response(
                response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=True, methods=["post"], permission_classes=[UserTypeCheck])
    def update_application(request, pk=None):
        """This method updates the status of user application"""

        # check for status_id
        try:
            request_id = getattr(request, "request_id", "N/A")
            logger.info(
                f"Updating application status for job with ID: {pk}",
                extra={"request_id": request_id},
            )

            if "status" not in request.data or not request.data["status"]:
                logger.warning(
                    "Recheck the status id", extra={"request_id": request_id}
                )
                return response.create_response(
                    "status-id not present or invalid",
                    status.HTTP_400_BAD_REQUEST,
                )

            response_message = validationClass.validate_id(pk, "job-id", Job)

            if response_message:
                return response.create_response(
                    response_message, status.HTTP_400_BAD_REQUEST
                )

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

            Applicants.objects.filter(employer_id=employer_id).update(
                status=request.data["status"]
            )

            return response.create_response(
                "Status has been updated!!", status.HTTP_200_OK
            )

        except Exception as e:
            logger.error(
                f"Error updating application status: {e}",
                extra={"request_id": request_id},
            )
            logger.error(traceback.format_exc())
            return response.create_response(
                response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    # @action(detail=True, methods=["post"])
    # def contact_us(request):
    #     if request.method == "POST":
    #         serializer = ContactUsSerializer(data=request.data)
    #         if serializer.is_valid():
    #             serializer.save()
    #             return Response({"message": "Message sent successfully!"})
    #         return Response(serializer.errors, status=400)

    #     return Response({"message": "Invalid request method"}, status=400)


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

    logger = logging.getLogger("jobs.UserViewSets")

    def update(self, request, *args, **kwargs):
        """
        Overriding the update method (used in PUT request),
        This method updates an existing user profile in the database.

        NOTE: tbl_user_auth has "id", tbl_user_profile has "user_id" as primary key.
        """
        try:
            request_id = getattr(self.request, "request_id", "N/A")
            if request.headers and "AccessToken" in request.headers:
                # decode the "user_id" from AccessToken
                try:
                    payload = jwt.decode(
                        request.headers["AccessToken"],
                        options={"verify_signature": False},
                    )
                except jwt.exceptions.DecodeError:
                    return response.create_response(
                        response.ACCESS_TOKEN_NOT_VALID, status.HTTP_400_BAD_REQUEST
                    )
                except Exception as err:
                    self.logger.exception(
                        "Exception occurred while decoding AccessToken",
                        extra={"request_id": request_id},
                    )
                    return response.create_response(
                        response.SOMETHING_WENT_WRONG,
                        status.HTTP_500_INTERNAL_SERVER_ERROR,
                    )
                else:
                    # check if the user_id is of type UUID or not
                    if payload and values.USER_ID in payload:
                        try:
                            uuid.UUID(payload[values.USER_ID])
                        except Exception as err:
                            self.logger.exception(
                                "Invalid user_id format in AccessToken",
                                extra={"request_id": request_id},
                            )
                            return response.create_response(
                                response.USER_INFORMATION_INVALID,
                                status.HTTP_406_NOT_ACCEPTABLE,
                            )
                    else:
                        self.logger.exception(
                            "User ID not present in AccessToken",
                            extra={"request_id": request_id},
                        )
                        return response.create_response(
                            response.ACCESS_TOKEN_NOT_VALID,
                            status.HTTP_406_NOT_ACCEPTABLE,
                        )
            else:
                self.logger.exception(
                    "AccessToken not present in headers",
                    extra={"request_id": request_id},
                )
                return response.create_response(
                    response.PERMISSION_DENIED + " You can't perform this operation",
                    status.HTTP_401_UNAUTHORIZED,
                )

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

            # perform check on payload["user_id"] if it exists in db or not
            try:
                user_id_auth = user_auth.objects.filter(
                    id=payload[values.USER_ID]
                ).exists()
                if not user_id_auth:
                    return response.create_response(
                        response.USER_INFORMATION_INVALID, status.HTTP_404_NOT_FOUND
                    )
            except Exception as err:
                self.logger.exception(
                    "Exception occurred while checking user_id in the database",
                    extra={"request_id": request_id},
                )
                return response.create_response(
                    response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            # Once everything's fine, update the db table
            # payload["user_id"] is used in the filter() not the pk present in url

            # get data from the request
            user_data = request.data

            # validate some data first
            try:
                validationClass.validate_fields(user_data)

            except Exception as err:
                self.logger.exception(
                    "Validation error while updating user data",
                    extra={"request_id": request_id},
                )
                return response.create_response(
                    err.__str__(), status.HTTP_400_BAD_REQUEST
                )

            try:
                # update in the tbl_user_profile
                User.objects.filter(user_id=payload[values.USER_ID]).update(**user_data)

                # update in the tbl_user_auth (only - user_name, user_email, user_type)
                tbl_user_auth_data = {
                    key: user_data[key]
                    for key in ("name", "email", "user_type")
                    if key in user_data
                }
                user_auth.objects.filter(id=payload[values.USER_ID]).update(
                    **tbl_user_auth_data
                )
            except IntegrityError:
                self.logger.warning(
                    "Supplied improper/same values", extra={"request_id": request_id}
                )
                return response.create_response(
                    "You've supplied either improper values or same values to update, Use a different one",
                    status.HTTP_401_UNAUTHORIZED,
                )
            except Exception as err:
                self.logger.exception(
                    "Exception occurred while updating the user data in db table",
                    extra={"request_id": request_id},
                )
                return response.create_response(
                    f"{response.SOMETHING_WENT_WRONG}",
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
            else:
                user_data = User.objects.get(user_id=payload[values.USER_ID])
                return response.create_response(
                    UserSerializer(user_data).data, status.HTTP_200_OK
                )

        except Exception as e:
            self.logger.exception(
                "Exception occurred in update method.", extra={"request_id": request_id}
            )
            return response.create_response(
                f"{response.SOMETHING_WENT_WRONG}",
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    @action(detail=True, methods=["get"])
    def jobs(self, request, pk=None):
        """
        API: /api/v1/user/{pk}/jobs
        This method finds out how many jobs a person has applied so far,
        pk here means primary key (basically the user_id)
        """

        try:
            request_id = getattr(request, "request_id", "N/A")
            if not validationClass.is_valid_uuid(pk):
                return response.create_response(
                    f"value {pk} isn't a correct id",
                    status.HTTP_404_NOT_FOUND,
                )

            jobs_data = None
            # get the applications submitted by this user
            applications = Applicants.objects.filter(user_id=pk).values(values.JOB_ID)
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
        except django.core.exceptions.ObjectDoesNotExist:
            return response.create_response(
                f"person id '{pk}' doesn't exist", status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            logger.exception(
                "Exception occurred in jobs method.", extra={"request_id": request_id}
            )
            return response.create_response(
                f"{response.SOMETHING_WENT_WRONG}",
                status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def get_application_status(serialized_data):
        if not serialized_data:
            logger.warning("Serialized data not provided")
            raise Exception("Serialized Data not provided")

        for job_data in serialized_data.data:
            job_id = job_data.get(values.JOB_ID)
            user_application = Applicants.objects.filter(job_id=job_id)
            if user_application.exists():
                status = user_application.first().status
                job_data.update({"status": status})

        return serialized_data


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

    logger = logging.getLogger("jobs.CompanyViewSets")  # class-specific self.logger

    @action(detail=False, methods=["get"])
    def jobs(self, request):
        """
        Method to get a list of jobs
        """

        try:
            request_id = getattr(request, "request_id", "N/A")
            serialized_company_data = self.serializer_class(
                self.get_queryset(), many=True
            )

            for company_data in serialized_company_data.data:
                company_id = company_data.get(values.COMPANY_ID)

                # get jobs data by company_id from database
                job_data = Job.objects.filter(company_id=company_id).values()
                company_data.update({"Jobs": job_data})

            return response.create_response(
                serialized_company_data.data, status.HTTP_200_OK
            )

        except Exception as e:
            self.logger.exception("Can't fetch jobs", extra={"request_id": request_id})
            return response.create_response(
                response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @action(detail=False, methods=["get"])
    def users(self, request):
        """
        Method to get the list of users
        """

        serialized_company_data = self.serializer_class(self.get_queryset(), many=True)
        for company_data in serialized_company_data.data:
            company_id = company_data.get(values.COMPANY_ID)

            # Get user information by company_id from database
            user_data = User.objects.filter(company_id=company_id).values()
            company_data.update({"User": user_data})

        return response.create_response(
            serialized_company_data.data, status.HTTP_200_OK
        )


class ContactUsViewSet(viewsets.ViewSet):
    def create(self, request):
        serializer = ContactUsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Message sent successfully!"}, status=201)
        return Response(serializer.errors, status=400)
