"""
This script perform checks on user_id, to find out
1. if the given user_id belongs to HR, if yes
    then is allow to perform certain things
2. if the given user_id belongs to normal user/employee, if yes
    then disallow.
"""

from rest_framework import permissions
import logging
from apps.jobs.models import User
from apps.jobs.constants import values
from apps.jobs.utils.validators import validationClass


class UserTypeCheck(permissions.BasePermission):
    EMPLOYER_ALLOWED_ACTIONS = {
        "job": ["apply", "create", "user", "list", "retrieve", "update_application"]
    }

    EMPLOYEE_ALLOWED_ACTIONS = {"job": ["list", "retrieve"]}
    logger = logging.getLogger("jobs.UserTypeCheck")

    def has_permission(self, request, view):
        """Return bool values based on user_type"""

        # Add the user_id to the JWT Later
        request_id = getattr(request, "request_id", "N/A")
        employer_id = request.data.get(values.EMPLOYER_ID)

        if not employer_id or not validationClass.is_valid_uuid(
            request.data[values.EMPLOYER_ID]
        ):
            self.logger.error(
                "Invalid employer_id or UUID validation failed",
                extra={"request_id": request_id},
            )
            return False

        if (
            not self.is_user_employer(employer_id)
            or view.action not in self.EMPLOYER_ALLOWED_ACTIONS[view.basename]
        ):
            self.logger.error(
                "Permission denied! User is not an employer",
                extra={"request_id": request_id},
            )
            return False

        self.logger.info(
            f"Permission granted for the user", extra={"request_id": request_id}
        )
        return super().has_permission(request, view)

    @staticmethod
    def is_user_employer(user_id, request):
        """Check if the user_id belongs to employer"""

        # check if the user_id belongs to any user
        logger = logging.getLogger("jobs.UserTypeCheck.is_user_employer")
        request_id = getattr(request, "request_id", "N/A")
        logger.info(
            f"Checking if user_id {user_id} belongs to an employer",
            extra={"request_id": request_id},
        )
        user_data = User.objects.filter(user_id=user_id, user_type__iexact="employer")
        if user_data.exists():
            logger.info(
                f"user_id {user_id} belongs to an employer",
                extra={"request_id": request_id},
            )
            return True
        else:
            logger.error(
                f"user_id {user_id} does not belong to an employer",
                extra={"request_id": request_id},
            )
            return False
