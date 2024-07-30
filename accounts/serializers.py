from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from rest_framework import serializers
from .models import OTP
from rest_framework.authtoken.models import Token

User = get_user_model()


class UserRegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['full_name', 'email', 'password', 'phone_number']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        otp = OTP.objects.create(user=user)
        otp.generate_otp()
        return user


class OTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)


class AuthTokenSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        user = authenticate(**data)
        if user and user.is_active:
            return user
        raise serializers.ValidationError('Invalid credentials')


class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Token
        fields = ['key']
