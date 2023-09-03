"""
This file contains serializers for Job, company and user object
and an implementation of uuid id hex value.

Note: the argumment `read_only=True` allows the field to only present
in the output. However at the time of crud opertions, it won't be present.
"""

import uuid
from rest_framework import serializers
from .models import Company, Job, User

# read_only=True allows the field to only present in the output
# however at the time of crud opertions, it won't be present.


class HexUUIDRepresentation(serializers.UUIDField):
    def to_representation(self, value):
        if isinstance(value, uuid.UUID):
            return str(value.hex)
        return super().to_representation(value)


class JobSerializer(serializers.ModelSerializer):
    """Job object serializer class"""

    job_id = HexUUIDRepresentation(read_only=True)

    class Meta:
        model = Job
        fields = "__all__"


class CompanySerializer(serializers.ModelSerializer):
    """Company object serializer class"""

    company_id = HexUUIDRepresentation(read_only=True)

    class Meta:
        model = Company
        fields = "__all__"


class UserSerializer(serializers.ModelSerializer):
    """User object serializer class"""

    user_id = HexUUIDRepresentation(read_only=True)

    class Meta:
        model = User
        fields = "__all__"
