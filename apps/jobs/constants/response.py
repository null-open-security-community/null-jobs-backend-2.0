"""This file contains the common response parameters that are sent with the response"""

from rest_framework.response import Response
import logging

logger = logging.getLogger("jobs.response")


def create_response(
    response_message: str, status_code, content_type="application/json"
):
    """
    This function returns HTTP Response with message, status_code and content_type
    """
    if 200 <= status_code <= 308:
        # logger.info(f"HTTP response data: {response_message}")
        response = {"data": response_message}
    elif status_code >= 400:
        logger.error(f"{response_message}")
        response = {"message": {"error": response_message}}
    return Response(response, status=status_code, content_type=content_type)


SOMETHING_WENT_WRONG = "something went wrong"
ACCESS_TOKEN_NOT_VALID = "Invalid access token provided"
PERMISSION_DENIED = "Permission denied!"
USER_INFORMATION_INVALID = "User information is not valid"
REQUEST_BODY_NOT_PRESENT = "Request body not present"
