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


logger = logging.getLogger(__name__)


class UserTypeCheck(permissions.BasePermission):
    EMPLOYER_ALLOWED_ACTIONS = {
        "job": ["apply", "create", "user", "list", "retrieve", "update_application"]
    }

    EMPLOYEE_ALLOWED_ACTIONS = {"job": ["list", "retrieve"]}

    def has_permission(self, request, view):
        """Return bool values based on user_type"""

        # Add the user_id to the JWT Later
        employer_id = request.data.get(values.EMPLOYER_ID)
        logger.info(f"Checking permissions for user with employer_id: {employer_id}")

        if not employer_id or not validationClass.is_valid_uuid(
            request.data[values.EMPLOYER_ID]
        ):
            logger.error("Invalid employer_id or UUID validation failed")
            return False

        if (
            not self.is_user_employer(employer_id)
            or view.action not in self.EMPLOYER_ALLOWED_ACTIONS[view.basename]
        ):
            logger.info("Permission denied for the user")
            return False

        logger.info("Permission granted for the user")
        return super().has_permission(request, view)

    @staticmethod
    def is_user_employer(user_id):
        """Check if the user_id belongs to employer"""

        # check if the user_id belongs to any user
        logger.info(f"Checking if user_id {user_id} belongs to an employer")
        user_data = User.objects.filter(user_id=user_id, user_type__iexact="employer")
        if user_data.exists():
            logger.info(f"user_id {user_id} belongs to an employer")
            return True
        else:
            logger.error(f"user_id {user_id} does not belong to an employer")
            return False
