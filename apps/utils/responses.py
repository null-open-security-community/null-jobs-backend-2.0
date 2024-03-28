from rest_framework import status
from rest_framework.response import Response
from rest_framework.exceptions import APIException

class InternalServerError(APIException):
    status_code = 500
    default_detail = 'Internal server error, try again later.'
    default_code = 'internal_server_error'


class Response201Created(Response):
    def __init__(self, id, *args, **kwargs):
        data = {
            'msg': 'Created',
            'id': id
        }

        super().__init__(data = data, status = status.HTTP_201_CREATED)
        