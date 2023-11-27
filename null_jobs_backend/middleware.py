# middleware.py
import uuid


class RequestIDMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Retrieve X-Request-ID from headers or generate a new one
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

        print(f"Middleware - X-Request-ID: {request_id}")

        # Attach the X-Request-ID to the request object
        request.request_id = request_id

        response = self.get_response(request)

        return response
