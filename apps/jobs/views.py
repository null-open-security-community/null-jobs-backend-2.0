
from django.db.models import Count
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from rest_framework import exceptions, parsers, status, viewsets
from rest_framework.views import APIView
from rest_framework.decorators import action
from rest_framework.response import Response

from apps.accounts.permissions import Moderator
from apps.jobs.constants import response, values
from apps.jobs.models import Company, ContactMessage, Job
from apps.jobs.serializers import CompanySerializer, ContactUsSerializer, JobSerializer, JobsCountByCategoriesSerializer
from apps.jobs.utils.validators import validationClass
from apps.utils.responses import InternalServerError

from .utils.user_permissions import UserTypeCheck


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

    queryset = Job.objects.annotate(total_applicants=Count("applicants"))
    serializer_class = JobSerializer
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["job_role", "location", "is_active", "category", "is_featured"]


    def create(self, request, *args, **kwargs):
        """Overriding the create method to include permissions"""

        # validate if the user is eligible to create a job posting or not
        if (
            not request.user
            or not request.user.user_type == "Employer"
            or not request.user.is_profile_completed
        ):
            return response.create_response(
                response.PERMISSION_DENIED
                + " You don't have permissions to create a job",
                status.HTTP_401_UNAUTHORIZED,
            )

        # fetching user profile to get the company to which
        # they belong to you
        request.data["company"] = Company.objects.get(creator=request.user)
        request.data["employer"] = request.user

        job = Job(**request.data)
        job.save()

        return Response(
            {"msg": "Created", "job_id": job.job_id}, status=status.HTTP_201_CREATED
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
                "Job id is not valid", status.HTTP_400_BAD_REQUEST
            )

        # if user is employer don't remove the job from the db table
        # else, set is_created=False and is_deleted=True
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

    @action(detail=False, methods=["get"])
    def get_trending_keywords(self, request):
        """
        API: /get_trending_keywords
        This API returns a list of trending keywords
        """

        try:
            return response.create_response(
                {"trending_keywords": values.trending_keywords}, status.HTTP_200_OK
            )
        except Exception:
            return response.create_response(
                response.SOMETHING_WENT_WRONG, status.HTTP_400_BAD_REQUEST
            )

    @action(detail=False, methods=["get"])
    @extend_schema(
        responses={200: JobsCountByCategoriesSerializer(many=True)},
        tags=["jobs"]
    )
    def get_count_by_categories(self, request):
        category_job_counts = Job.objects.values('category').annotate(count=Count('job_id'))
        return Response(JobsCountByCategoriesSerializer(category_job_counts, many=True).data)


    
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
    parser_classes = [parsers.MultiPartParser, parsers.FormParser]

    # Basic filters
    filter_backends = [DjangoFilterBackend]
    filterset_fields = ["name", "location"]

    def list(self, request):
        """
        Method to return a list of companies available,
        Along with the count of active jobs present in the company
        """

        try:
            company_data = self.queryset.filter(is_deleted=False)
            serialized_company_data = self.serializer_class(
                company_data, many=True, context={"request": request}
            )

            return response.create_response(
                serialized_company_data.data, status.HTTP_200_OK
            )
        except Exception:
            return response.create_response(
                response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    @extend_schema(exclude=True)
    def update(self, request, *args, **kwargs):
        """
        API: UPDATE /company/{id}
        Overriding update method to first check for
        Moderator and Employer user_type associated with the user, and
        then perform an update
        """

        # check if the user_id present in the request belongs to Employer or Moderator
        # if not (
        #     UserTypeCheck.is_user_employer(request.user_id)
        #     or Moderator().has_permission(request)
        # ):
        #     return response.create_response(
        #         response.PERMISSION_DENIED
        #         + " You don't have permissions to update company details",
        #         status.HTTP_401_UNAUTHORIZED,
        #     )

        # return super().update(request, *args, **kwargs)
        raise exceptions.MethodNotAllowed()

    @extend_schema(exclude=True)
    def destroy(self, request, pk=None, *args, **kwargs):
        """
        API: DELETE /company/{id}
        Overriding destroy method to first check for
        Moderator and Employer associated with the user, and
        then perform an update.
        """

        # check if the user_id present in the request belongs to Employer or Moderator
        # if not (
        #     UserTypeCheck.is_user_employer(request.user_id)
        #     or Moderator().has_permission(request)
        # ):
        #     return response.create_response(
        #         response.PERMISSION_DENIED
        #         + " You don't have permissions to delete a company",
        #         status.HTTP_401_UNAUTHORIZED,
        #     )

        # # check if the job is already deleted or not
        # company_data = Company.objects.filter(
        #     company_id=pk, is_created=False, is_deleted=True
        # )
        # if company_data.exists():
        #     return response.create_response(
        #         "Given company_id does not exist or already deleted",
        #         status.HTTP_404_NOT_FOUND,
        #     )

        # # if user is employer don't remove the company from the db table
        # # else, set is_created=False and is_deleted=True
        # if UserTypeCheck.is_user_employer(request.user_id):
        #     try:
        #         company_data = Company.objects.filter(company_id=pk)
        #         company_data.update(is_created=False, is_deleted=True)
        #         serialized_company_data = CompanySerializer(company_data, many=True)
        #         return response.create_response(
        #             serialized_company_data.data, status.HTTP_200_OK
        #         )
        #     except Exception:
        #         return response.create_response(
        #             response.SOMETHING_WENT_WRONG, status.HTTP_500_INTERNAL_SERVER_ERROR
        #         )

        # return super().destroy(request, *args, **kwargs)
        raise exceptions.MethodNotAllowed()

    def create(self, request, *args, **kwargs):
        # check if the user is a employer or not
        # only employers are allowed to create companies
        if not request.user or not request.user.user_type == "Employer":
            raise exceptions.PermissionDenied()

        serializer = CompanySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # create a company
        try:
            company, created = Company.objects.get_or_create(
                creator=request.user, defaults=serializer.data
            )

            if not created:
                for key, value in serializer.data.items():
                    setattr(company, key, value)

            if request.data.get("picture") is not None:
                company.picture = request.data.get("picture")

            company.save()
        except Exception as e:
            print(e)
            raise InternalServerError()

        # once the user is created
        # set profile completion so jobs can be created
        user = request.user
        user.is_profile_completed = True
        user.save()

        return Response(
            {"msg": "Created", "company_id": company.company_id},
            status.HTTP_201_CREATED,
        )

    @action(detail=False, methods=["get"])
    def me(self, request):
        if not request.user.is_profile_completed:
            raise exceptions.PermissionDenied()

        # fetch user profile which has the company associated
        company = Company.objects.get(creator=request.user)

        return Response(self.serializer_class(company).data)


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
    http_method_names = ["post", "get"]

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
            if not Moderator().has_permission(request):
                return response.create_response(
                    "Access forbidden for non-moderator user",
                    status.HTTP_403_FORBIDDEN,
                )
            else:
                return super().list(request, *args, **kwargs)
        else:
            return super().list(request, *args, **kwargs)
