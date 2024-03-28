from rest_framework.permissions import BasePermission


class IsJobSeeker(BasePermission):
    """Custom permissions that allow only job seekers to access
    the views"""

    def has_permission(self, request, view):
        return request.user.user_type == "Job Seeker"
    

class IsProfileCompleted(BasePermission):
    """Custom permissions that allow only job seekers or employers with complete profile
    to access the views"""

    def has_permission(self, request, view):
        return request.user.is_profile_complete
    

class IsEmployer(BasePermission):
    """Custom permissions that allow only the employers to access
    the view"""

    def has_permission(self, request, view):
        return request.user.user_type == "Employer"


class Moderator(BasePermission):
    """
    This class contains everything related to operations
    belong to Moderator. Moderator user is different from
    Admin user, but has some level of responsibilities and
    access to resources.
    """

    def has_permission(self, request, view):
        """Method to check if the given user_id belongs to moderator or not"""
        return request.user.is_moderator
    
