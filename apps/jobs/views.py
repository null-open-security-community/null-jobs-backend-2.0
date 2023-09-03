import uuid
import django.core.exceptions
from apps.jobs.validators import validationClass
from rest_framework import viewsets, status
from apps.jobs.models import Job, User, Company
from apps.jobs.serializers import JobSerializer, UserSerializer, CompanySerializer
from rest_framework.decorators import action
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models.expressions import RawSQL

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

    def retrieve(self, request, pk=None):
        """
        retrieve the data of given job id
        """

        validator = validationClass()
        if not validator.is_valid_uuid(pk):
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
            # numberOfApplications = User.objects.filter(job_id=job_id).count()
            number_of_applicants = User.objects.filter(
                user_id__in=RawSQL(
                    """
                SELECT user_id FROM tbl_user_profile
                WHERE job_id=%s
                """,
                    [job_id],
                )
            ).count()
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
        validator = validationClass()
        checkUUID = validator.is_valid_uuid(pk)
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
        user_data = User.objects.filter(job_id=job_id)
        serialized_data = UserSerializer(
            user_data, many=True, context={"request": request}
        )
        return Response(serialized_data.data)


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

    def create(self, request, *args, **kwargs):
        """
        Overriding the create method (used in POST request),
        This method creates a new user profile in the database.
        """

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

        ## Save the data into the database
        # Update the fields
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        data = serializer.validated_data
        headers = self.get_success_headers(data)
        return Response(
            serializer.data, status=status.HTTP_201_CREATED, headers=headers
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
            person_data = self.queryset.filter(
                user_id__in=RawSQL(
                    """
                SELECT user_id FROM tbl_user_profile
                WHERE user_id=%s
                """,
                    [pk],
                )
            )

            if person_data.exists():
                job_id = person_data.get().job_id.hex
                # jobs_data=Job.objects.filter(job_id=job_id)
                jobs_data = Job.objects.filter(
                    job_id__in=RawSQL(
                        """
                    SELECT job_id FROM tbl_job
                    WHERE job_id=%s
                    """,
                        [job_id],
                    )
                )

            # here we serialize the data, for comm.
            serialized_jobs_data = JobSerializer(
                jobs_data, many=True, context={"request": request}
            )
            return Response(serialized_jobs_data.data)
        except django.core.exceptions.ObjectDoesNotExist:
            return Response(
                {"message": f"person id '{pk}' doesn't exist"},
                content_type="application/json",
            )


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
