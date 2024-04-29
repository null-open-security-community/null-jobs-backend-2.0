from django.db.models import BooleanField, Case, Value, When
from drf_spectacular.utils import extend_schema
from rest_framework import exceptions, parsers, permissions, status, viewsets, filters
import django_filters.rest_framework as df_filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts import permissions as custom_permissions
from apps.accounts.models import User
from apps.userprofile.models import UserProfile, FavoriteProfiles
from apps.userprofile.serializers import (
    UploadFilesSerializer,
    UserProfileRequestSerializer,
    UserProfileResponseSerializer,
    ShortlistProfileRequestSerializer
)
from apps.utils.pagination import  DefaultPagination
from apps.utils.responses import InternalServerError, Response201Created, Response200Success


class UserProfileFilter(df_filters.FilterSet):
    profession = df_filters.BaseInFilter(field_name='profession')
    experience = df_filters.BaseInFilter(field_name='experience')

    class Meta:
        model = UserProfile
        fields = ['profession', 'experience']


@extend_schema(tags=["user profile"])
class UserProfileViewSet(viewsets.ModelViewSet):
    """
    UserProfile object viewsets
    API: /api/v1/user
    Database: tbl_user_profile
    Functions:
        1. create or update user
        2. list users/specific user
        3. check jobs applied by a specific user
    """

    queryset = UserProfile.objects.all()
    serializer_class = UserProfileResponseSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter, df_filters.DjangoFilterBackend]
    search_fields = ['profession', 'address']
    filterset_class = UserProfileFilter
    pagination_class = DefaultPagination

    def get_queryset(self):
        queryset = super().get_queryset()

        queryset = queryset.annotate(
            is_favorite=Case(
                When(favoriteprofiles__employer=self.request.user, then=Value(True)),
                default=Value(False),
                output_field=BooleanField(),
            )
        )

        return queryset


    @extend_schema(tags=["user profile"], request=UserProfileRequestSerializer)
    def create(self, request, *args, **kwargs):
        """A job seeker has a user profile so when a user
        wants to update a user this has to be accessed only by
        job seeker whose profile it is
        """
        user = request.user

        # check if the user is of valid type only the
        # job seekers can update their profiles
        if user.user_type == "Employer":
            raise exceptions.PermissionDenied()

        serializer = UserProfileRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # updating user name when its not the same as the previous name
        if request.user.name != serializer.get_name():
            print("Updating the name with {}".format(serializer.name))
            # only name can be changed in the auth user itself
            users_updated = User.objects.filter(id=request.user.id).update(
                name=serializer.get_name()
            )

            if not users_updated:
                raise InternalServerError()

        # updating user profile data
        user_profile_data = serializer.data
        user_profile, created = UserProfile.objects.get_or_create(
            user=user, defaults=user_profile_data
        )

        # updating the user profile wiht the rest of the data
        if not created:
            for key, value in user_profile_data.items():
                setattr(user_profile, key, value)

        user_profile.save()

        return Response(
            UserProfileResponseSerializer(user_profile).data,
            status=status.HTTP_201_CREATED,
        )

    @extend_schema(tags=["user profile"])
    @action(detail=False, methods=["get"])
    def me(self, request):
        """
        API: /user/me
        Returns user profile data in the response based on
        user_id present in the Authorization Header
        """
        # this view is for job seekers for their profile
        if request.user.user_type == "Employer":
            raise exceptions.PermissionDenied()

        user_profile = UserProfile.objects.get(user=request.user)
        print(user_profile.resume)

        return Response(
            UserProfileResponseSerializer(user_profile).data, status=status.HTTP_200_OK
        )

    @extend_schema(exclude=True)
    def destroy(self, request, *args, **kwargs):
        raise exceptions.MethodNotAllowed("DELETE")

    @extend_schema(tags=["user profile"], exclude=True)
    def update(self, request, *args, **kwargs):
        raise exceptions.MethodNotAllowed("PUT")


class UplaodDocumentsView(APIView):
    permission_classes = [permissions.IsAuthenticated, custom_permissions.IsJobSeeker]
    parser_classes = [parsers.MultiPartParser, parsers.FormParser]

    @extend_schema(request=UploadFilesSerializer, tags=["user profile"])
    def post(self, request):
        try:
            user_profile = UserProfile.objects.get(user=request.user)
        except UserProfile.DoesNotExist:
            raise exceptions.NotFound("The profile for this user is absent")
        except Exception as e:
            print(e)
            raise InternalServerError(str(e))

        # set is_profile_completed to done
        if request.data.get("resume") is not None:
            print("here")
            users_updated = User.objects.filter(id=request.user.id).update(
                is_profile_completed=True
            )

            user_profile.resume = request.data.get("resume")

        if request.data.get("cover_letter") is not None:
            user_profile.cover_letter = request.data.get("cover_letter")

        if request.data.get("profile_picture") is not None:
            user_profile.profile_picture = request.data.get("profile_picture")

        user_profile.save()

        print(user_profile.resume)

        return Response201Created(request.user.id)

@extend_schema(tags=["user profile"])
class ShortlistProfileViewset(APIView):
    permission_classe = [permissions.IsAuthenticated, custom_permissions.IsEmployer]

    @extend_schema(request=ShortlistProfileRequestSerializer)
    def post(self, request):
        # validate request body
        serializer = ShortlistProfileRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            user_profile = UserProfile.objects.get(id = serializer.data.get('profile_id'))
        except UserProfile.DoesNotExist:
            raise exceptions.NotFound()
        except Exception as e:
            raise InternalServerError()

        # when profile is being shortlisted
        if serializer.data.get('shortlist'):
            # fetching or creatig the profile
            shortlisted_profile, created = FavoriteProfiles.objects.get_or_create(
                employer = request.user, favorite_profile=user_profile,
                defaults={'employer': request.user, 'favorite_profile': user_profile}
            )

            # if already exists then profile is already shortlisted
            if not created:
                return Response200Success('Profile already shortlisted')
            
            # profile shortlist success
            return Response200Success('Profile shortlisted')
        
        try:
            fav_profile = FavoriteProfiles.objects.get(employer=request.user, favorite_profile=user_profile)
        except FavoriteProfiles.DoesNotExist:
            return Response200Success('Profile is not shortlisted')
        except Exception as e:
            raise InternalServerError()
        
        fav_profile.delete()

        return Response200Success('Profile de shortlisted successfully')
    