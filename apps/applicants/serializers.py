from rest_framework import serializers

from apps.applicants.models import Applicants
from apps.applicants import constants


class ApplicantModelSerializer(serializers.ModelSerializer):
    class Meta:
        model = Applicants
        fields = ['id', 'job', 'user', 'status', 'created_at', 'updated_at', 'is_deleted', 'is_active']
        read_only_fields = ['id', 'created_at', 'updated_at', 'is_deleted', 'is_active']  # Fields that should not be editable


class ApplyToJobSerializer(serializers.Serializer):
    job_id = serializers.CharField(required=True)

class UpdateApplicationStatusSerializer(serializers.Serializer):
    application_id = serializers.CharField(required=True)
    status = serializers.ChoiceField(choices=constants.STATUS_CHOICES, required=True)

