import re
import uuid

from django.core.exceptions import ValidationError
from django.core.validators import (
    EmailValidator,
    MaxValueValidator,
    MinValueValidator,
    URLValidator,
)
from datetime import datetime
from apps.jobs.constants import values


class validationClass:
    """
    This class provides validation functionality for files such as resumes and images.
    Currently supports validation for:
    1. Resume files
    2. Image files
    """

    @staticmethod
    def is_valid_uuid(value):
        # Expects value in proper format(with hyphens) of uuid, returns bool value
        try:
            uuid_value = uuid.UUID(str(value))
        except ValueError:
            return False
        else:
            return str(uuid_value) == str(value)

    @staticmethod
    def validate_id(uuid, idtype: str, model_class):
        """perform checks on uuid, and if it
        exists in the database."""

        if not validationClass.is_valid_uuid(uuid):
            return {"error": f"{idtype} isn't a valid UUID", "status": False}

        if model_class.objects.filter(pk=uuid).count() < 1:
            return {"error": f"This {idtype} doesn't exist", "status": False}

        return {"success": f"id {uuid} exists", "status": True}

    def image_validation(self, image_file):
        # check size
        filesize = image_file.size / (1024 * 1024)
        if filesize > 10:
            return (False, "Profile Image shouldn't exceed 10mb")

        allowed_image_extensions = ["png", "jpeg", "jpg"]
        allowed_content_types = ["image/png", "image/jpg", "image/jpeg"]
        image_file_extension = image_file.name.split(".")[-1].lower()
        upload_file_to_storage = False

        # filename check
        if not re.match("[\w\-]+\.\w{3,4}$", image_file.name):
            return (False, "Image File name isn't appropriate")

        # Allowed content-type/extensions check
        if (
            image_file_extension in allowed_image_extensions
            and image_file.content_type in allowed_content_types
        ):
            # check signatures
            if (image_file_extension == "png") and (
                image_file.file.read()[:8].hex().upper().encode("ASCII")
                == "89504E470D0A1A0A".encode("ASCII")
            ):
                upload_file_to_storage = True
            elif (image_file_extension in ["jpg", "jpeg"]) and (
                image_file.file.read()[:8].hex().upper().startswith("FFD8")
            ):
                upload_file_to_storage = True
            else:
                return (False, "Image File type isn't supported")
        else:
            return (False, "Oops, Wrong Image file submitted")

        if upload_file_to_storage:
            return (True, "File is valid")

    def resume_validation(self, resume_file):
        # check size (shouldn't exceed 10mb)
        filesize = resume_file.size / (1024 * 1024)
        if filesize > 10:
            return (False, "Resume File size shouldn't exceed 10mb")
        else:
            ## check characters present in the file name
            # for example: Only allowed those files that
            # includes only alphanumeric, hyphen and a period
            if not re.match("[\w\-]+\.\w{3,4}$", resume_file.name):
                return (False, "Resume File name isn't appropriate")

            # check file extension & content_type
            upload_file_to_storage = False
            allowed_file_extensions = ["pdf", "docx", "doc"]
            allowed_content_types = [
                "application/pdf",
                "application/msword",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ]
            file_extension = resume_file.name.split(".")[-1].lower()
            if (
                file_extension in allowed_file_extensions
                and resume_file.content_type in allowed_content_types
            ):
                # check file signature thing
                if file_extension == "pdf":
                    if resume_file.file.read()[:4].hex().upper().encode(
                        "ASCII"
                    ) == "25504446".encode("ASCII"):
                        upload_file_to_storage = True
                elif file_extension == "docx":
                    if resume_file.file.read()[:4].hex().upper().encode(
                        "ASCII"
                    ) == "504B0304".encode("ASCII"):
                        upload_file_to_storage = True
                elif file_extension == "doc":
                    if resume_file.file.read()[:4].hex().upper().encode(
                        "ASCII"
                    ) == "D0CF11E0A1B11AE1".encode("ASCII"):
                        upload_file_to_storage = True
                else:
                    return (False, "Resume File type is not supported")
            else:
                return (False, "Oops, wrong resume file submitted")

        if upload_file_to_storage:
            return (True, "File is valid")

    @staticmethod
    def validate_fields(data):
        """
        This method is used to validate some specific fields
        present in the given data (format: dictionary)
        """

        # Remove sensitive fields from the data
        validationClass.remove_sensitive_fields(data) 

        def validate_email(email):
            """
            Validate email format.
            """
            email_validator = EmailValidator()
            try:
                email_validator(email)
            except ValidationError as err:
                raise ValidationError(
                    f"Invalid email value provided\n\nReason: {err.__str__()}"
                )
            
        def validate_work_experience(work_experience: dict):
            """Validate the fields present in work_experience
            Structure: 
            {
                "work_experience": [
                    {},
                    {}
                ]
            }
            """

            if not isinstance(work_experience, dict):
                raise Exception("Invalid data provided")
            
            experience_list = work_experience.get("experience", [])
            dates = []
            
            for experience_dict in experience_list:
                if not isinstance(experience_dict, dict):
                    raise Exception(f"Provided data {experience_dict} is not in JSON format")
                
                experience_dict_copy = experience_dict.copy()
                for key, value in experience_dict_copy.items():
                    if key not in values.WORK_EXPERIENCE_REQUIRED_FIELDS and key not in values.WORK_EXPERIENCE_OPTIONAL_FIELDS:
                        raise Exception(f"Invalid key '{key}' provided")

                    if key == values.FROM or (key == values.TILL and value != "present"):
                        try:
                            date_value = datetime.strptime(value, "%d/%m/%Y")
                            dates.append(date_value)
                        except ValueError:
                            raise Exception(f"Invalid date format for key '{key}'")
                    elif key == values.TILL and value == "present":
                        date_value = datetime.now()
                        dates.append(date_value)

                    elif key in [values.COMPANY_NAME, values.DESIGNATION] and isinstance(value, str):
                        if not re.match(r"^[a-zA-Z0-9&\s\-.,\'()]{1,100}$", value):
                            raise Exception(f"Invalid value provided to '{key}'")
                    
                # Handle optional fields default data
                for key, default_value in values.WORK_EXPERIENCE_OPTIONAL_FIELDS.items():
                    if key not in experience_dict:
                        experience_dict[key] = default_value
                    elif key == values.FOUND_THROUGH_NULL and not isinstance(experience_dict[key], bool):
                        raise Exception(f"Key '{key}' should contain a boolean value")

            return True, dates

        duplicate_data = data.copy()
        for field_name, field_value in duplicate_data.items():
            try:
                if field_name == "age":
                    MinValueValidator(15)(field_value)
                    MaxValueValidator(100)(field_value)
                elif field_name == "email":
                    validate_email(field_value)
                elif field_name == "website":
                    if not re.search("^(https?|ftp)://[^\s/$.?#].[^\s]*$", field_value):
                        raise ValidationError(f"Invalid {field_name} value provided")
                elif field_name in ["name", "full_name", "message"]:
                    if not re.match(r'^[a-zA-Z0-9 .,\'"-]*$', field_value):
                        raise ValidationError(
                            {"error": f"Invalid {field_name} format."}
                        ) 
                elif field_name == "work_experience":
                    # Here we will calculate the total experience in the field and then
                    # add the key called 'experience' in the data
                    value = validate_work_experience(field_value)
                    if isinstance(value[1], list):
                        total_experience = 0
                        for i in range(0, len(value[1]), 2):
                            from_date, till_date = value[1][i:i+2]
                            difference = till_date.year - from_date.year

                            if till_date.month < from_date.month or (till_date.month == from_date.month and till_date.day < from_date.day):
                                difference -= 1
                            total_experience += difference
                    
                        data.update({"experience": total_experience})

            except ValidationError as err:
                raise ValidationError(
                    f"Given {field_name} doesn't contain a valid value\n\nReason: {err.__str__()}"
                )

    @staticmethod
    def remove_sensitive_fields(data: dict) -> None:
        """
        This method removes the sensitive fields which are not
        intended for normal users to update. Especially where we
        are performing update using large number of fields.
        """

        removable_fields = ("user_type", "is_created", "is_deleted", "experience")
        [data.pop(field, None) for field in removable_fields]