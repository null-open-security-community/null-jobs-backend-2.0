"""
This script perform checks on user_id, to find out
1. if the given user_id belongs to HR, if yes
    then is allow to perform certain things
2. if the given user_id belongs to normal user/employee, if yes
    then disallow.
"""

from rest_framework import permissions

from apps.jobs.constants import values
from apps.jobs.models import User
from apps.jobs.utils.validators import validationClass


class UserTypeCheck(permissions.BasePermission):
    EMPLOYER_ALLOWED_ACTIONS = {
        "job": [
            "apply",
            "create",
            "user",
            "list",
            "retrieve",
            "update_application",
            "update",
            "delete",
        ]
    }

    EMPLOYEE_ALLOWED_ACTIONS = {"job": ["list", "retrieve"]}

    def has_permission(self, request, view):
        """Return bool values based on user_type"""

        # Add the user_id to the JWT Later
        employer_id = request.user_id

        if not employer_id or not validationClass.is_valid_uuid(employer_id):
            return False

        if (
            not self.is_user_employer(employer_id)
            or view.action not in self.EMPLOYER_ALLOWED_ACTIONS[view.basename]
        ):
            return False

        return super().has_permission(request, view)

    @staticmethod
    def is_user_employer(user_id):
        """Check if the user_id belongs to employer"""

        # check if the user_id belongs to any user
        user_data = User.objects.filter(user_id=user_id, user_type__iexact=values.EMPLOYER)
        return True if user_data.exists() else False
