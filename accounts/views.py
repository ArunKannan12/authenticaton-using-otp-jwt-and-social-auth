from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from .serializers import UserRegisterSerializer,LoginSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .models import CustomUser
import pyotp
from django.http import JsonResponse
from .utils import send_otp_via_email
from django.utils import timezone
from django.contrib.auth import authenticate

class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            user.secret_key=pyotp.random_base32()
            user.is_active=False
            user.save()
            send_otp_via_email(user)
            return Response({
                'data': serializer.data,
                'message': f"Hi {user.first_name}, thanks for signing up! A passcode has been sent to your email."
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)





class SendOTPView(APIView):
    """Send OTP to user on email"""
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return JsonResponse({'error':'email is required'},status=400)

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)

        send_otp_via_email(user)  # Send OTP email
        return JsonResponse({'message': 'OTP sent successfully to your email'}, status=200)

class VerifyOTPView(APIView):
    """Verify OTP entered by the user"""
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')
        if not email or not otp:
            return JsonResponse({'error':'email and otp are required'},status=40)
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
        if not user.secret_key or not user.otp_expiry:
            return JsonResponse({'error': 'OTP not generated'}, status=400)

        if timezone.now() > user.otp_expiry:
            return JsonResponse({'error': 'OTP has expired'}, status=400)

        totp = pyotp.TOTP(user.secret_key,interval=60)
        if totp.verify(otp,valid_window=1):
            user.is_verified=True
            user.is_active = True  # You can mark user as active or verified
            user.save()
            return JsonResponse({'message': 'OTP verified successfully'}, status=200)
        return JsonResponse({'error': 'Invalid or expired OTP'}, status=400)


class LoginUserView(GenericAPIView):
    serializer_class=LoginSerializer

    def post(self,request):
        serializer=self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email=serializer.validated_data.get('email')
        full_name = serializer.validated_data.get('full_name')
        access_token = serializer.validated_data.get('access_token')
        refresh_token = serializer.validated_data.get('refresh_token')


        return Response({
            'email':email,
            'message': f"Welcome {full_name}",
            'access_token': access_token,
            'refresh_token': refresh_token
        }, status=status.HTTP_200_OK)