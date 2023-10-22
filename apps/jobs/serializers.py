"""
This file contains serializers for Job, company and user object
and an implementation of uuid id hex value.

Note: the argumment `read_only=True` allows the field to only present
in the output. However at the time of crud opertions, it won't be present.
"""

import uuid
from re import findall

from rest_framework import serializers

from apps.jobs.models import Applicants, Company, Job, User

# read_only=True allows the field to only present in the output
# however at the time of crud opertions, it won't be present.


class JobSerializer(serializers.ModelSerializer):
    """Job object serializer class"""

    class Meta:
        """
        we are exlucding some fields in the to_representation method,
        so we don't need to explicitly add the exclude field which contains
        a dict of values to be excluded from the serialized data.
        "__all__" is necessary because if it's present here, then
        Job data fields wouldn't be accessible.
        """

        model = Job
        fields = "__all__"

    def to_representation(self, instance):
        """
        this method customize the serialized representation of an object,
        using this, at the time of serialization, we can modify the data.
        in this case we are combining several field's result into one, and
        removing those fields from the serializer.data
        """

        data = super().to_representation(instance)

        # Combine fields
        data["description"] = {
            "About": instance.description,
            "Job Responsibilities": instance.job_responsibilities,
            "Skills Required": instance.skills_required,
            "Educations/Certifications": instance.education_or_certifications,
        }

        # Exclude individual fields from the response
        fields_to_exclude = [
            "job_responsibilities",
            "skills_required",
            "education_or_certifications",
        ]
        for field_name in fields_to_exclude:
            data.pop(field_name)

        return data


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

    def to_representation(self, instance):
        """
        Here, this method is used to combine some fields into one, and exclude
        those fields. Also, we are handling one case to represent social_handles
        as a list of strings
        """

        data = super().to_representation(instance)

        # Extract the URLs from social handles
        found_url_patterns = findall("https?:\/\/?[\w\.\/?=]+", instance.social_handles)
        if found_url_patterns:
            instance.social_handles = found_url_patterns

        data["Contact"] = {
            "Address": instance.address,
            "Phone": instance.phone,
            "Website": instance.website,
            "Email": instance.email,
            "Social Handles": instance.social_handles,
        }

        fields_to_exclude = ["email", "phone", "website", "social_handles"]
        for field_name in fields_to_exclude:
            data.pop(field_name)

        return data


class ApplicantsSerializer(serializers.ModelSerializer):
    """Applicants object serializer class"""

    class Meta:
        model = Applicants
        fields = "__all__"
