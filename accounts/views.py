from django.shortcuts import render
from rest_framework.generics import GenericAPIView
from .serializers import (UserRegisterSerializer,
                          LoginSerializer,
                          PasswordResetRequestSerializer,
                          SetNewPasswordSerializer)
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .models import CustomUser
import pyotp
from django.http import JsonResponse
from .utils import send_otp_via_email
from django.utils import timezone
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str,DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import timezone
from datetime import timedelta


class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            expiry_time = timezone.now() + timedelta(minutes=5)
            user.secret_key=pyotp.random_base32()
            user.otp_expiry = expiry_time
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
        if user.is_verified:
            return JsonResponse({'error': 'Account already verified. No need to send OTP again.'}, status=400)
        expiry_time = timezone.now() + timedelta(minutes=5)
        user.secret_key = pyotp.random_base32()  # Reset secret key on new OTP request
        user.otp_expiry = expiry_time 
        user.is_active = False # Set OTP expiry time (e.g., 5 minutes)
        user.save()
        send_otp_via_email(user)  # Send OTP email
        return JsonResponse({'message': 'OTP sent successfully to your email'}, status=200)

class VerifyOTPView(APIView):
    """Verify OTP entered by the user"""
    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        if not email or not otp:
            return JsonResponse({'error':'email and otp are required'},status=400)
        
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)
        
        if user.is_verified:
            return JsonResponse({'error': 'Account already verified'}, status=400)

        
        if not user.secret_key or not user.otp_expiry:
            return JsonResponse({'error': 'OTP not generated'}, status=400)

        if timezone.now() > user.otp_expiry:
            return JsonResponse({'error': 'OTP has expired. Please request a new one.'}, status=400)


        totp = pyotp.TOTP(user.secret_key,interval=60)
        if totp.verify(otp,valid_window=1):
            user.is_verified=True
            user.is_active = True  # You can mark user as active or verified
            user.secret_key = None  # Clear key to invalidate OTP
            user.otp_expiry = None  # Clear expiry
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
    

class TestAuthenticationView(GenericAPIView):
    permission_classes=[IsAuthenticated]

    def get(self,request):
        data={
            'msg':'it works'
        }
        return Response(data,status=status.HTTP_200_OK)



class PasswordResetRequestView(GenericAPIView):
    serializer_class=PasswordResetRequestSerializer
    def post(self,request):
        serializer=self.serializer_class(data=request.data,context={'request':request})
        if serializer.is_valid(raise_exception=True):
            return Response({'message': 'Password reset link sent if the email is registered.'}, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            


class passwordResetConfirm(GenericAPIView):
    def get(self,request,uidb64,token):
        try:
            user_id=force_str(urlsafe_base64_decode(uidb64))
            user =CustomUser.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user,token):
                return Response({
                    'success': False,
                    'message': 'Token is invalid or has expired',
                    'uidb64': uidb64,
                    'token': token
                }, status=status.HTTP_401_UNAUTHORIZED)

            return Response({
                'success': True,
                'message': 'Credentials are valid',
                'uidb64': uidb64,
                'token': token
            }, status=status.HTTP_200_OK)
        except (DjangoUnicodeDecodeError, CustomUser.DoesNotExist):
            return Response({
                'success': False,
                'message': 'Token is invalid or user not found'
            }, status=status.HTTP_401_UNAUTHORIZED)
        


class SetNewPasswordView(GenericAPIView):
    serializer_class=SetNewPasswordSerializer

    def post(self,request):
        serializer=self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({
                'message': 'Password reset successfully'
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        