"""
This file contains class based view to define middleware.
"""

from os import getenv
from typing import Any

import jwt
from rest_framework import status
from rest_framework.renderers import JSONRenderer

from apps.accounts.models import User as user_auth
from apps.accounts.urls import public_apis_accounts
from apps.jobs.constants import response, values
from apps.jobs.urls import public_apis_jobs
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
        self.excluded_paths = ["/api/docs/", "/api/schema/", "/api/redoc/"]
        self.excluded_paths.extend(public_apis_accounts)
        self.excluded_paths.extend(public_apis_jobs)

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
        6. Authorization Header
        7. Existence of user_id in token value of Authorization Header

        Return type: [exit_status, message]
        """

        response_tuple = self.check_and_decode_access_token(request)
        if response_tuple[0]:
            return response_tuple

        response_tuple = self.check_user_exists(request)
        if response_tuple[0]:
            return response_tuple

        return (0, "Exit Successfully")

    def check_and_decode_access_token(self, request) -> tuple:
        """method to perform the following things
        1. check 'Authorization: Bearer tokenValue' in request headers
        2. decode the 'tokenValue' and add a key named "userId" to the request
        """

        # check for excluded paths
        if request.path in self.excluded_paths:
            return (0, "Rejecting Authorization Token check")

        if not (request.headers and "Authorization" in request.headers):
            return (1, "Missing Token, User not available")

        # decode the Authorization token value and add the user_id to the request
        # as a separate key

        keywords = ["Bearer"]

        try:
            # get the authorization token value, format - ["Bearer", "tokenValue"]
            authorization_token = request.headers["Authorization"].split(" ")
            if len(authorization_token) != 2 or authorization_token[0] not in keywords:
                raise Exception

            payload = jwt.decode(
                authorization_token[1],
                getenv("DJANGO_SECRET_KEY"),
                algorithms=["HS256"],
                options={"verify_signature": True},
            )
            if values.USER_ID in payload and validationClass.is_valid_uuid(
                payload[values.USER_ID]
            ):
                request.user_id = payload[values.USER_ID]
            else:
                raise Exception
        except (jwt.DecodeError, Exception, jwt.exceptions.InvalidSignatureError):
            return (1, "Invalid Authorization Token")

        return (0, "Exit Successfully")

    def process_response(self, response):
        pass

    def check_user_exists(self, request):
        """
        check if user_id exists in the db or not
        database table for ref: tbl_user_auth

        Expected Extra arguments:
        1. request.path
        """

        if request.path in self.excluded_paths:
            return (0, "Rejecting user_id existence check")

        try:
            user_id = request.user_id
            response = validationClass().validate_id(user_id, "id", user_auth)
            if not response["status"]:
                return (1, "User does not exist")
            return (0, "Exit Successfully")
        except Exception:
            return (1, "Something Went Wrong")
