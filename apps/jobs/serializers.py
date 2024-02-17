"""
This file contains serializers for Job, company and user object
and an implementation of uuid id hex value.

Note: the argumment `read_only=True` allows the field to only present
in the output. However at the time of crud opertions, it won't be present.
"""

import uuid
from re import findall

from rest_framework import serializers

from apps.jobs.models import Applicants, Company, ContactMessage, Job, User

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

        if data:
            try:
                # Combine fields
                data.update(
                    {
                        "description": {
                            "About": data.pop("description", None),
                            "Job Responsibilities": data.pop(
                                "job_responsibilities", None
                            ),
                            "Skills Required": data.pop("skills_required", None),
                            "Educations/Certifications": data.pop(
                                "education_or_certifications", None
                            ),
                        }
                    }
                )

            except Exception:
                data = {"error": {"message": "Something Went Wrong"}}

        return data


class CompanySerializer(serializers.ModelSerializer):
    """Company object serializer class"""

    class Meta:
        model = Company
        fields = "__all__"

    def to_representation(self, instance):
        """
        Overriding this method for a better representation of social_profiles field
        """

        if not instance:
            return {}

        data = super().to_representation(instance)

        social_profiles_value = data.get("social_profiles", "")
        try:
            if instance.social_profiles:
                found_url_patterns = findall(
                    "((https?:\/\/)?[\w\.\/?=]+)", social_profiles_value
                )
                instance.social_profiles = [url[0] for url in found_url_patterns]

            data.update({"social_profiles": instance.social_profiles})

        except Exception as err:
            # We can also raise an exception here but this time, I am returning
            # error message in the data
            return {
                "error": {"message": f"Something Went Wrong\n\nReason: {err.__str__()}"}
            }

        return data


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

        if data:
            # Extract the URLs from social handles
            try:
                if instance.social_handles:
                    found_url_patterns = findall(
                        "((https?:\/\/)?[\w\.\/?=]+)", data.pop("social_handles", "")
                    )
                    if found_url_patterns:
                        instance.social_handles = [url[0] for url in found_url_patterns]

                data.update(
                    {
                        "Contact": {
                            "Address": data.pop("address", None),
                            "Phone": data.pop("phone", None),
                            "Website": data.pop("website", None),
                            "Email": data.pop("email", None),
                            "Social Handles": instance.social_handles,
                        }
                    }
                )

            except Exception as err:
                # We can also raise an exception here but this time, I am returning
                # error message in the data
                data = {
                    "error": {
                        "message": f"Something Went Wrong\n\nReason: {err.__str__()}"
                    }
                }

        return data


class ApplicantsSerializer(serializers.ModelSerializer):
    """Applicants object serializer class"""

    class Meta:
        model = Applicants
        fields = "__all__"


class ContactUsSerializer(serializers.ModelSerializer):
    """Contact us object serializer class"""

    class Meta:
        model = ContactMessage
        fields = ("full_name", "email", "message")

        def validate_message(self, value):
            """Checks if the message is in Text Format"""
            try:
                value.encode("utf-8").decode("utf-8")
            except UnicodeEncodeError:
                raise serializers.ValidationError("Message must be valid UTF-8 text.")
            return value
