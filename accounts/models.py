
from django.utils import timezone
from django.conf import settings
import random
import string
from django.contrib.auth.models import AbstractUser
from django.db import models
from accounts.managers import CustomUserManager


class User(AbstractUser):
    username = models.CharField(max_length=40, blank=True, null=True)
    full_name = models.CharField(max_length=30, blank=False, null=False)
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=15, blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name']

    def __str__(self):
        return self.email


class OTP(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6, blank=True, null=True)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def generate_otp(self):
        self.otp = ''.join(random.choices(string.digits, k=6))
        self.save()

    def is_expired(self):
        expiration_time = timezone.now() - timezone.timedelta(minutes=10)
        return self.created_at < expiration_time
