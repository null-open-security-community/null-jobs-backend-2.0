from rest_framework import viewsets
from rest_framework.response import Response

# from .serializers import SampleSerializer


class SampleViewSet(viewsets.ViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    def retrieve(self, request, pk=None):
        print(":Here")
        return Response({"message": "Hello World!"})
