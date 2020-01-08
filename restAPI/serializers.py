from rest_framework import serializers

from restAPI.models import *


class PhoneBookSerializer(serializers.Serializer):
    class Meta:
        model = PhoneBook
        fields = '__all__'
