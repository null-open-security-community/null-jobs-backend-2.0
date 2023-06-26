from rest_framework import serializers


class SampleSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    title = serializers.CharField(required=False, allow_blank=True)
    