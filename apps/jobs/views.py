import uuid
from re import search

import django.core.exceptions
import jwt
from django.db.models.expressions import RawSQL
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.accounts.models import User as user_auth
from apps.jobs.models import Applicants, Company, Job, User
from apps.jobs.serializers import (
    ApplicantsSerializer,
    CompanySerializer,
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
    filterset_fields = ["company", "location"]

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
            return Response({"message": err.messages}, status=status.HTTP_404_NOT_FOUND)
        else:
            serialized_job_data = self.serializer_class(
                jobs_data, many=True, context={"request": request}
            )

            # get number of applicants
            if serialized_job_data:
                serialized_job_data = self.get_number_of_applicants(serialized_job_data)

            return Response(serialized_job_data.data, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        """Overriding the create method to include permissions"""

        employer_id = request.data.get("employer_id")

        if not employer_id or not UserTypeCheck.is_user_employer(
            request.data["employer_id"]
        ):
            return Response(
                {
                    "error": "Permission Denied! You don't have permissions to create jobs"
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )

        return super().create(request, *args, **kwargs)

    def retrieve(self, request, pk=None):
        """
        retrieve the data of given job id
        """

        if not validationClass.is_valid_uuid(pk):
            return Response(
                {"message": f"value {pk} isn't a correct id"},
                status=status.HTTP_404_NOT_FOUND,
            )

        # filter based on pk
        job_data = self.queryset.raw("SELECT * FROM tbl_job WHERE job_id=%s", [pk])
        serialized_job_data = self.serializer_class(job_data, many=True)
        serialized_job_data = self.get_number_of_applicants(serialized_job_data)
        return Response(serialized_job_data.data, status=status.HTTP_200_OK)

    def get_number_of_applicants(self, serialized_data):
        """
        return serialized_data with a new field added to it,
        that contains count of number of applicants.
        """

        if not serialized_data:
            raise Exception("Serialized data not provided")

        for jobdata in serialized_data.data:
            job_id = jobdata.get("job_id")
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
            return Response(
                {"message": f"value {pk} isn't a correct id"},
                status=status.HTTP_404_NOT_FOUND,
                content_type="application/json",
            )

        # get the specific job or return 404 if not found
        jobdata = Job.objects.get(pk=pk)
        job_id = jobdata.job_id.hex

        # get all the users object
        user_data = Applicants.objects.filter(job_id=job_id)
        serialized_data = ApplicantsSerializer(
            user_data, many=True, context={"request": request}
        )
        return Response(serialized_data.data)

    @action(detail=True, methods=["post"])
    def apply(self, request, pk=None):
        """Apply job functionality implementation"""

        common_response_parameters = {
            "status": status.HTTP_400_BAD_REQUEST,
            "content_type": "application/json",
        }

        job_id = pk
        user_id = request.data["user_id"]

        # validate, if both of them exists or not
        response_message = validationClass.validate_id(
            job_id, "job-id", Job
        ) or validationClass.validate_id(user_id, "user-id", User)
        if response_message:
            return Response(
                response_message,
                status=status.HTTP_400_BAD_REQUEST,
                content_type="application/json",
            )

        # Check whether the user has applied for the job before
        apply_job_status = Applicants.objects.filter(
            job_id=job_id, user_id=user_id
        ).exists()
        if apply_job_status:
            common_response_parameters["status"] = status.HTTP_200_OK
            return Response(
                {"message": "You have already applied for this Job"},
                **common_response_parameters,
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
                return Response(
                    {"message": f"You don't have {key} updated"},
                    **common_response_parameters,
                )

        # Get the employer-id from the database
        # employer-id always exists in the db, without this job can't be created
        employer_id = (
            Job.objects.filter(job_id=job_id)
            .values("employer_id")
            .first()["employer_id"]
        )

        # Prepare the overall dictionary to save into the database
        # Add job-id, user-id, employer-id to the applyjob_data
        applyjob_data["job_id"] = job_id
        applyjob_data["user_id"] = user_id
        applyjob_data["employer_id"] = employer_id

        # Add this application into the database
        applyjob = Applicants(**applyjob_data)
        applyjob.save()

        return Response(
            {"message": "You have successfully applied for this job"},
            **common_response_parameters,
        )

    @action(detail=True, methods=["post"], permission_classes=[UserTypeCheck])
    def update_application(self, request, pk=None):
        """This method updates the status of user application"""

        common_response_parameters = {
            "status": status.HTTP_400_BAD_REQUEST,
            "content_type": "application/json",
        }

        # check for status_id
        if "status" not in request.data or not request.data["status"]:
            return Response(
                {"error": "status-id not present or invalid"},
                **common_response_parameters,
            )

        # check if job_id is valid & present in db or not
        response_message = validationClass.validate_id(pk, "job-id", Job)
        if response_message:
            return Response(response_message, **common_response_parameters)

        # check if the given employer_id has posted the job (given by job-id)
        employer_id = request.data["employer_id"]
        job_employer_id = (
            Job.objects.filter(job_id=pk)
            .values("employer_id")
            .first()["employer_id"]
            .hex
        )
        if job_employer_id != employer_id:
            return Response(
                {"error": "This job isn't posted by the given employer id"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
                content_type="application/json",
            )

        # Update the status of current application
        try:
            Applicants.objects.filter(employer_id=employer_id).update(
                status=request.data["status"]
            )
        except Exception as err:
            return Response(
                {"error": "Something went wrong"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content_type=common_response_parameters["content_type"],
            )
        else:
            common_response_parameters["status"] = status.HTTP_200_OK
            return Response(
                {"message": "Status has been updated!!"}, **common_response_parameters
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
        Overriding the create method (used in POST request),
        This method creates a new user profile in the database.
        """
        common_response_parameters = {
            "status": status.HTTP_400_BAD_REQUEST,
            "content_type": "application/json",
        }

        if request.headers and "AccessToken" in request.headers:
            # decode the "user_id" from AccessToken
            try:
                payload = jwt.decode(
                    request.headers["AccessToken"], options={"verify_signature": False}
                )
            except jwt.exceptions.DecodeError:
                return Response(
                    {"error": "AccessToken is not valid"}, **common_response_parameters
                )
            except Exception as err:
                common_response_parameters[
                    "status"
                ] = status.HTTP_500_INTERNAL_SERVER_ERROR
                return Response(
                    {"error": "Something went wrong"}, **common_response_parameters
                )
            else:
                # check if the user_id is of type UUID or not
                if payload and "user_id" in payload:
                    try:
                        uuid.UUID(payload["user_id"])
                    except Exception as err:
                        return Response(
                            {
                                "Error": "wrong user information provided in the AccessToken"
                            },
                            status=status.HTTP_400_BAD_REQUEST,
                            content_type="application/json",
                        )
                else:
                    return Response(
                        {"error": "AccessToken is not valid"},
                        **common_response_parameters,
                    )
        else:
            common_response_parameters["status"] = status.HTTP_401_UNAUTHORIZED
            return Response(
                {"error": "Permission Denied! You can't perform this operation"},
                **common_response_parameters,
            )

        # Perform check on data with PUT Request
        if not request.data:
            return Response(
                {"error": "request body can't be empty"}, **common_response_parameters
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

        # Check if the given user_id actually belongs to the user
        # This check is necessary because only specific users can update their profile

        # get the user_id from the url path
        if user_id := search("\w{32}", request.stream.path):
            user_id = user_id[0]

        # if case, if someone crafts a request in such a way that
        # user_id in accessToken and user_id in the api path are same

        # perform check on database as well
        if user_id == payload["user_id"]:
            # check payload["user_id"] in tbl_user_auth
            # check for /user/{user_id} performs by-default, we don't have to write for it.
            try:
                user_id_auth = user_auth.objects.filter(
                    user_id=payload["user_id"]
                ).exists()
                if not user_id_auth:
                    common_response_parameters["status"] = status.HTTP_404_NOT_FOUND
                    return Response(
                        {"error": "wrong information provided in the AccessToken"},
                        **common_response_parameters,
                    )
            except Exception as err:
                return Response(
                    {"error": "Something went wrong"}, **common_response_parameters
                )
        else:
            common_response_parameters["status"] = status.HTTP_401_UNAUTHORIZED
            return Response(
                {"error": "given user_id doesn't belong to the user"},
                **common_response_parameters,
            )

        # Once everything's fine, update the db table
        # payload["user_id"] is used in the filter() not the pk present in url

        # get data from the request
        user_data = request.data
        try:
            # update in the tbl_user_profile
            User.objects.filter(user_id=payload["user_id"]).update(**user_data)

            # update in the tbl_user_auth (only - user_name, user_email, user_type)
            tbl_user_auth_data = {
                key: user_data[key]
                for key in ("name", "email", "user_type")
                if key in user_data
            }
            user_auth.objects.filter(user_id=payload["user_id"]).update(
                **tbl_user_auth_data
            )
        except:
            common_response_parameters["status"] = status.HTTP_500_INTERNAL_SERVER_ERROR
            return Response(
                {"error": "Something went wrong"}, **common_response_parameters
            )
        else:
            user_data = User.objects.get(user_id=payload["user_id"])
            common_response_parameters["status"] = status.HTTP_200_OK
            return Response(
                UserSerializer(user_data).data, **common_response_parameters
            )

    @action(detail=True, methods=["get"])
    def jobs(self, request, pk=None):
        """
        API: /api/v1/user/{pk}/jobs
        This method finds out how many jobs a person has applied so far,
        pk here means primary key (basically the user_id)
        """

        try:
            jobs_data = None
            # get the applications submmited by this user
            applications = Applicants.objects.filter(user_id=pk).values("job_id")
            if applications.exists():
                # get the job_ids
                applications_count = applications.count()
                jobs_id = [
                    applications[n]["job_id"] for n in range(0, applications_count)
                ]

                # get the jobs data
                jobs_data = Job.objects.filter(job_id__in=jobs_id)
                # here we serialize the data, for comm.
                serialized_jobs_data = JobSerializer(
                    jobs_data, many=True, context={"request": request}
                )
                serialized_jobs_data = self.get_application_status(serialized_jobs_data)
                return Response(serialized_jobs_data.data)
            else:
                return Response(
                    {"message": "You haven't applied to any job"},
                    status=status.HTTP_200_OK,
                    content_type="application/json",
                )
        except django.core.exceptions.ObjectDoesNotExist:
            return Response(
                {"message": f"person id '{pk}' doesn't exist"},
                content_type="application/json",
            )

    def get_application_status(self, serialized_data):
        if not serialized_data:
            raise Exception("Serialized Data not provided")

        for job_data in serialized_data.data:
            job_id = job_data.get("job_id")
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
            companyId = company_data.get("company_id")

            # get jobs data by company_id from database
            # .values() returns the QuerySet
            # jobData = Job.objects.filter(company=companyId).values()
            job_data = Job.objects.filter(
                job_id__in=RawSQL(
                    """
                SELECT job_id from tbl_job
                WHERE company_id=%s
                """,
                    [companyId],
                )
            ).values()
            company_data.update({"Jobs": job_data})

        return Response(serialized_company_data.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=["get"])
    def users(self, request):
        """
        Method to get the list of users
        """

        serialized_company_data = self.serializer_class(self.get_queryset(), many=True)
        for company_data in serialized_company_data.data:
            company_id = company_data.get("company_id")

            # Get user information by company_id from database
            user_data = User.objects.filter(
                user_id__in=RawSQL(
                    """
                SELECT user_id from tbl_user_profile
                WHERE company_id=%s
                """,
                    [company_id],
                )
            ).values()
            company_data.update({"User": user_data})

        return Response(serialized_company_data.data, status=status.HTTP_200_OK)
