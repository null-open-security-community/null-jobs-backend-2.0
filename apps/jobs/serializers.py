"""
This file contains serializers for Job, company and user object
and an implementation of uuid id hex value.

Note: the argumment `read_only=True` allows the field to only present
in the output. However at the time of crud opertions, it won't be present.
"""

import uuid

from rest_framework import serializers

from apps.jobs.models import Applicants, Company, Job, User

# read_only=True allows the field to only present in the output
# however at the time of crud opertions, it won't be present.


class JobSerializer(serializers.ModelSerializer):
    """Job object serializer class"""

    class Meta:
        model = Job
        fields = "__all__"


class CompanySerializer(serializers.ModelSerializer):
    """Company object serializer class"""

    class Meta:
        model = Company
        fields = "__all__"


class UserSerializer(serializers.ModelSerializer):
    """User object serializer class"""

    class Meta:
        model = User
        fields = "__all__"


class ApplicantsSerializer(serializers.ModelSerializer):
    """Applicants object serializer class"""

    class Meta:
        model = Applicants
        fields = "__all__"
