"""
This file contains class based view to define middleware.
"""

from typing import Any

import jwt
from rest_framework import status
from rest_framework.renderers import JSONRenderer

from apps.jobs.constants import response, values
from apps.jobs.utils.validators import validationClass


class ValidateRequest:
    """
    This class is used to validate the request coming from the frontend
    and before the response is sent back to the frontend
    """

    def __init__(self, get_response) -> None:
        """run only once when the web server starts"""

        self.get_response = get_response
        self.response_obj = response
        self.excluded_paths = ["/register/"]

    def __call__(self, request, *args: Any, **kwds: Any) -> Any:
        """Called once per request"""

        # Perform things here on Request before it goes to later parts
        data = self.process_request(request=request)
        if data[0]:
            response = self.response_obj.create_response(
                data[1], status.HTTP_401_UNAUTHORIZED
            )

            response.accepted_renderer = JSONRenderer()
            response.accepted_media_type = "application/json"
            response.renderer_context = {}
            response.render()
            return response

        response = self.get_response(request)
        # Perform things here on the response coming from views

        return response

    def process_request(self, request) -> Any:
        """
        This method is used to perform validation on following items
        1. HOST
        2. Content-Type
        3. HTTP Method
        4. X-Request-ID
        5. Content-Length
        6. AccessToken

        Return type: [exit_status, message]
        """
        return self.check_and_decode_access_token(request)

    def check_and_decode_access_token(self, request) -> tuple:
        """method to perform the following things
        1. check 'AccessToken' in request headers
        2. decode the 'AccessToken' and add a new key to the request
        """

        # check for excluded paths
        if request.path in self.excluded_paths:
            return (0, "Rejecting AccessToken check")

        if not (request.headers and "AccessToken" in request.headers):
            return (1, "AccessToken is not present")

        # decode the access token and add the user_id to the request
        # as a separate key
        try:
            payload = jwt.decode(
                request.headers["AccessToken"],
                algorithms=["HS256"],
                options={"verify_signature": False},
            )
            if values.USER_ID in payload and validationClass.is_valid_uuid(
                payload[values.USER_ID]
            ):
                request.user_id = payload[values.USER_ID]
            else:
                return (1, "Invalid AccessToken")
        except (jwt.DecodeError, Exception):
            return (1, "Invalid AccessToken")

        return (0, "Exit Successfully")

    def verify_jwt(self, jwt_token):
        pass

    def process_response(self, response):
        pass
