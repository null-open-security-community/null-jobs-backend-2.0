import uuid
from re import search

import django.core.exceptions
import jwt
from django.db.models.expressions import RawSQL
from django.db.utils import IntegrityError
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.accounts.models import User as user_auth
from apps.jobs.constants import response, values
from apps.jobs.models import Applicants, Company, Job, User, ContactMessage
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
            jobs_data = self.queryset.filter(**filters_dict)
        except django.core.exceptions.ValidationError as err:
            return response.create_response(err.messages, status.HTTP_404_NOT_FOUND)
        else:
            serialized_job_data = self.serializer_class(
                jobs_data, many=True, context={"request": request}
            )

            # get number of applicants
            if serialized_job_data:
                serialized_job_data = self.get_number_of_applicants(serialized_job_data)

            return response.create_response(
                serialized_job_data.data, status.HTTP_200_OK
            )

    def create(self, request, *args, **kwargs):
        """Overriding the create method to include permissions"""

        employer_id = request.data.get(values.EMPLOYER_ID)

        if not employer_id or not UserTypeCheck.is_user_employer(
            request.data[values.EMPLOYER_ID]
        ):
            return response.create_response(
                response.PERMISSION_DENIED
                + " You don't have permissions to create jobs",
                status.HTTP_401_UNAUTHORIZED,
            )

        return super().create(request, *args, **kwargs)

    def retrieve(self, request, pk=None):
        """
        retrieve the data of given job id
        """

        if not validationClass.is_valid_uuid(pk):
            return response.create_response(
                f"value {pk} isn't a correct id",
                status.HTTP_404_NOT_FOUND,
            )

        # filter based on pk
        job_data = Job.objects.filter(job_id=pk)
        serialized_job_data = self.serializer_class(job_data, many=True)
        if serialized_job_data:
            serialized_job_data = self.get_number_of_applicants(serialized_job_data)
        return response.create_response(serialized_job_data.data, status.HTTP_200_OK)

    def get_number_of_applicants(self, serialized_data):
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
        ) or validationClass.validate_id(user_id, "user-id", User)
        if response_message:
            return response.create_response(
                response_message, status.HTTP_400_BAD_REQUEST
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
        employer_id = (
            Job.objects.filter(job_id=job_id)
            .values(values.EMPLOYER_ID)
            .first()[values.EMPLOYER_ID]
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
        if response_message:
            return response.create_response(
                response_message, status.HTTP_400_BAD_REQUEST
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

        if request.headers and "AccessToken" in request.headers:
            # decode the "user_id" from AccessToken
            try:
                payload = jwt.decode(
                    request.headers["AccessToken"], options={"verify_signature": False}
                )
            except jwt.exceptions.DecodeError:
                return response.create_response(
                    response.ACCESS_TOKEN_NOT_VALID, status.HTTP_400_BAD_REQUEST
                )
            except Exception as err:
                print("Exception occurred while decoding AccessToken")
                return response.create_response(
                    response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
                )
            else:
                # check if the user_id is of type UUID or not
                if payload and values.USER_ID in payload:
                    try:
                        uuid.UUID(payload[values.USER_ID])
                    except Exception as err:
                        return response.create_response(
                            response.USER_INFORMATION_INVALID,
                            status.HTTP_406_NOT_ACCEPTABLE,
                        )
                else:
                    return response.create_response(
                        response.ACCESS_TOKEN_NOT_VALID, status.HTTP_406_NOT_ACCEPTABLE
                    )
        else:
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
            user_id_auth = user_auth.objects.filter(id=payload[values.USER_ID]).exists()
            if not user_id_auth:
                return response.create_response(
                    response.USER_INFORMATION_INVALID, status.HTTP_404_NOT_FOUND
                )
        except Exception as err:
            print(
                "Exception occurred while performing check on user_id in the database"
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
            return response.create_response(err.__str__(), status.HTTP_400_BAD_REQUEST)

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
            user_data = User.objects.get(user_id=payload[values.USER_ID])
            return response.create_response(
                UserSerializer(user_data).data, status.HTTP_200_OK
            )

    @action(detail=True, methods=["get"])
    def jobs(self, request, pk=None):
        """
        API: /api/v1/user/{pk}/jobs
        This method finds out how many jobs a person has applied so far,
        pk here means primary key (basically the user_id)
        """

        try:
            if not validationClass.is_valid_uuid(pk):
                return response.create_response(
                    f"value {pk} isn't a correct id",
                    status.HTTP_404_NOT_FOUND,
                )
            jobs_data = None
            # get the applications submmited by this user
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

    @action(detail=False, methods=["get"])
    def jobs(self, request):
        """
        Method to get a list of jobs
        """

        serialized_company_data = self.serializer_class(self.get_queryset(), many=True)
        for company_data in serialized_company_data.data:
            company_id = company_data.get(values.COMPANY_ID)

            # get jobs data by company_id from database
            # .values() returns the QuerySet
            # jobData = Job.objects.filter(company=companyId).values()
            job_data = Job.objects.filter(company_id=company_id).values()
            company_data.update({"Jobs": job_data})

        return response.create_response(
            serialized_company_data.data, status.HTTP_200_OK
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
    http_method_names = ["get", "post"]

    def get_queryset(self):
        return ContactMessage.objects.all()

    @action(detail=False, methods=["post"])
    def create_contact_message(self, request):
        full_name = request.data.get("full_name")
        email = request.data.get("email")
        message = request.data.get("message")

        validation_error = validationClass.validate_contact_data(
            full_name, email, message
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
            user = request.user
            if UserTypeCheck.is_user_employer:
                return Response(
                    {"Access forbidden for non-moderator user"},
                    status=status.HTTP_403_FORBIDDEN,
                )
            else:
                return super().list(request, *args, **kwargs)
        else:
            return super().list(request, *args, **kwargs)
