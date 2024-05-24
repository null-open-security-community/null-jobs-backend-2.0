import json
from uuid import uuid4

from rest_framework import serializers

from apps.accounts.serializers import UserSerializer as UserAuthSerializer


class EducationSerializer(serializers.Serializer):
    id = serializers.CharField(allow_null=True, default=uuid4)
    from_date = serializers.CharField()
    till_date = serializers.CharField()
    grade = serializers.CharField()
    course = serializers.CharField()
    university = serializers.CharField()
    course_type = serializers.CharField()


class ProfessionalSkillsSerializer(serializers.Serializer):
    last_used = serializers.IntegerField()
    total_yoe = serializers.IntegerField()
    skill_name = serializers.CharField()


class WorkExperienceSerializer(serializers.Serializer):
    id = serializers.UUIDField(allow_null=True, default=uuid4)
    from_date = serializers.CharField()
    till_date = serializers.CharField()
    company_id = serializers.CharField(allow_null=True, default=None)
    description = serializers.CharField()
    designation = serializers.CharField()
    company_name = serializers.CharField()
    found_through_null = serializers.BooleanField()


class UserProfileRequestSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)

    # user table serializer
    user = UserAuthSerializer(read_only=True)

    # comps
    name = serializers.CharField(write_only=True)
    experience = serializers.CharField()
    gender = serializers.CharField(allow_null=True)
    age = serializers.IntegerField(allow_null=True)
    profession = serializers.CharField()
    address = serializers.CharField()
    phone = serializers.CharField()
    website = serializers.URLField()
    social_handles = serializers.URLField(allow_null=True, default=None)

    # description
    about = serializers.CharField()
    education = serializers.ListField(child=EducationSerializer())
    professional_skills = serializers.ListField(child=ProfessionalSkillsSerializer())
    work_experience = serializers.ListField(child=WorkExperienceSerializer())

    is_favorite = serializers.BooleanField(read_only=True)

    def get_name(self):
        return self.validated_data.get("name")


class UserProfileResponseSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True)

    # user table serializer
    user = UserAuthSerializer(read_only=True)

    # comps
    name = serializers.CharField(write_only=True)
    experience = serializers.CharField()
    gender = serializers.CharField(allow_null=True)
    age = serializers.IntegerField(allow_null=True)
    profession = serializers.CharField()
    address = serializers.CharField()
    phone = serializers.CharField()
    website = serializers.URLField()
    social_handles = serializers.URLField(allow_null=True, default=None)

    # description
    about = serializers.CharField()
    education = serializers.ListField(child=EducationSerializer())
    professional_skills = serializers.ListField(child=ProfessionalSkillsSerializer())
    work_experience = serializers.ListField(child=WorkExperienceSerializer())

    # files sections
    resume = serializers.FileField(allow_null=True, default=None, read_only=True)
    profile_picture = serializers.ImageField(
        allow_null=True, default=None, read_only=True
    )
    cover_letter = serializers.FileField(allow_null=True, default=None, read_only=True)

    is_favorite = serializers.BooleanField(read_only=True)

    def get_name(self):
        return self.validated_data.get("name")


class UploadFilesSerializer(serializers.Serializer):
    # files sections
    resume = serializers.FileField(allow_null=True, required=False)
    profile_picture = serializers.ImageField(allow_null=True, required=False)
    cover_letter = serializers.FileField(allow_null=True, required=False)


class ShortlistProfileRequestSerializer(serializers.Serializer):
    shortlist = serializers.BooleanField(default=True)
    profile_id = serializers.CharField()
