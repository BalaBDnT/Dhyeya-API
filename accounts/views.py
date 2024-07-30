from django.contrib.auth import get_user_model
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.authtoken.models import Token
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated

from .serializers import UserRegisterSerializer, OTPVerifySerializer
from .models import OTP

User = get_user_model()


class userAuthentication(APIView):
    def post(self, request, action):
        if action == 'register':
            return self.register(request)
        elif action == 'verifyotp':
            return self.verify_otp(request)
        elif action == 'login':
            return self.user_login(request)
        elif action == 'logout':
            return self.user_logout(request)
        else:
            return Response({'message': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

    def register(self, request):
        serializer = UserRegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            otp = OTP.objects.get(user=user)
            subject = 'Your OTP Code'
            message = render_to_string('emails/otp_email.html', {
                'user': user,
                'otp': otp.otp,
            })
            email = EmailMessage(
                subject=subject,
                body=message,
                from_email='no-reply@example.com',
                to=[user.email],
            )
            email.content_subtype = 'html'
            email.send(fail_silently=False)
            return Response({'detail': 'User created. Check your email for OTP.'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def verify_otp(self, request):
        serializer = OTPVerifySerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp_code = serializer.validated_data['otp']
            try:
                user = User.objects.get(email=email)
                otp = OTP.objects.get(user=user, otp=otp_code)
                if otp.is_verified:
                    return Response({'detail': 'OTP already verified.'}, status=status.HTTP_400_BAD_REQUEST)
                if otp.is_expired():
                    return Response({'detail': 'OTP expired.'}, status=status.HTTP_400_BAD_REQUEST)
                otp.is_verified = True
                otp.save()
                user.is_active = True
                user.save()
                return Response({'detail': 'OTP verified. User activated.'}, status=status.HTTP_200_OK)
            except (User.DoesNotExist, OTP.DoesNotExist):
                return Response({'detail': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def user_login(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = None
        try:
            user = User.objects.get(email=email)
            if not user.is_active:
                return Response({
                    'message': 'Your account is inactive. Please check your email for the activation link.'
                }, status=status.HTTP_403_FORBIDDEN)
        except ObjectDoesNotExist:
            pass
        if user:
            user = authenticate(email=email, password=password)

            if user is not None:
                token, created = Token.objects.get_or_create(user=user)
                if not created and token.created < timezone.now() - timezone.timedelta(days=1):
                    token.delete()
                    token = Token.objects.create(user=user)
                    token.expires = timezone.now() + timezone.timedelta(days=1)
                    token.save()
                return Response(
                    {'token': token.key, 'email': email, 'full name': user.full_name}, status=status.HTTP_200_OK)
        return Response({'message': 'Invalid credentials'}, status=status.HTTP_400_BAD_REQUEST)

    def user_logout(self, request):
        try:
            request.user.auth_token.delete()
            return Response({'message': 'Successfully logged out.'}, status=status.HTTP_200_OK)
        except Token.DoesNotExist:
            return Response({'message': 'User is not logged in.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
