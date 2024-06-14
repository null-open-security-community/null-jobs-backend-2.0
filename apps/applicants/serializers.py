from rest_framework import serializers

from apps.applicants import constants
from apps.applicants.models import Applicants
from apps.jobs.serializers import JobSerializer
from apps.userprofile.serializers import UserProfileResponseSerializer


class ApplicantJobSerializer(serializers.Serializer):
    job_id = serializers.UUIDField()
    job_role = serializers.CharField()


class ApplicantModelSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)
    job = ApplicantJobSerializer()
    user = UserProfileResponseSerializer()
    created_at = serializers.DateTimeField()
    updated_at = serializers.DateTimeField()
    is_deleted = serializers.BooleanField()
    is_active = serializers.BooleanField()
    status = serializers.CharField()


class ApplyToJobSerializer(serializers.Serializer):
    job_id = serializers.CharField(required=True)


class UpdateApplicationStatusSerializer(serializers.Serializer):
    application_id = serializers.CharField(required=True)
    status = serializers.ChoiceField(choices=constants.STATUS_CHOICES, required=True)






class AppliedJobSerializer(serializers.ModelSerializer):
    job = JobSerializer(read_only=True)

    class Meta:
        model = Applicants
        fields = [
            'id',
            'job',
            'created_at',
            'updated_at',
            'is_deleted',
            'is_active',
            'status'
        ]


