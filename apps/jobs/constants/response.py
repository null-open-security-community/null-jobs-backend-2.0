"""This file contains the common response parameters that are sent with the response"""

from rest_framework.response import Response


def create_response(
    response_message: str, status_code, content_type="application/json"
):
    """
    This function returns HTTP Response with message, status_code and content_type
    """

    if 200 <= status_code <= 308:
        response = {"data": response_message}
    elif status_code >= 400:
        response = {"error": {"message": response_message}}
    return Response(response, status=status_code, content_type=content_type)

ACCESS_TOKEN = "AccessToken"
SOMETHING_WENT_WRONG = "Something Went Wrong"
ACCESS_TOKEN_NOT_VALID = "Invalid Access Token Provided"
PERMISSION_DENIED = "Permission Denied!"
USER_INFORMATION_INVALID = "User Information is Not Valid"
REQUEST_BODY_NOT_PRESENT = "Request Body Not Present"
ACCESS_TOKEN_NOT_PRESENT = "Access Token Not Present"
USER_DATA_NOT_PRESENT = "User Data is Not Present"