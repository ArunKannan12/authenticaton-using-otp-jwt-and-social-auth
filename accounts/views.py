from rest_framework.generics import GenericAPIView
from .serializers import (UserRegisterSerializer,
                          LoginSerializer,
                          PasswordResetRequestSerializer,
                          SetNewPasswordSerializer,
                          LogoutuserSerializer,
                          CustomUserSerializer,
                          SetNewPasswordSerializer,
                          FacebookLoginSerializer
                          
                          )
import requests

from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .models import CustomUser
import pyotp
from django.http import JsonResponse
from .utils import send_otp_via_email
from django.utils import timezone
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated,AllowAny
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str,DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from datetime import timedelta
from rest_framework_simplejwt.tokens import RefreshToken
from django.conf import settings

from google.auth.transport.requests import Request
from google.oauth2 import id_token
from google.auth import exceptions

from django.contrib.auth import get_user_model

user=get_user_model

class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        if serializer.is_valid():
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
            'full_name':full_name,
            'message': f"Welcome {serializer.validated_data.get('first_name')}",
            'access_token': access_token,
            'refresh_token': refresh_token
        }, status=status.HTTP_200_OK)
    


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

class LogoutUserView(GenericAPIView):
    serializer_class = LogoutuserSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'detail': 'Logged out successfully.'}, status=status.HTTP_200_OK)
    
class ProfileView(APIView):
    permission_classes=[IsAuthenticated]


    def get(self,request):
        user=request.user
        serializer=CustomUserSerializer(user)
        return Response(serializer.data,status=status.HTTP_200_OK)


    def patch(self,request):
        user = request.user
        if user.auth_provider.lower() != 'email':
            return Response(
                {"detail":"profile updated allowed only for email authenticated users "}
            ,status=status.HTTP_403_FORBIDDEN)
        

        serializer = CustomUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
class GoogleAuthView(APIView):

    permission_classes = [AllowAny]

    def post(self, request):
        # Get the ID token sent from frontend
        id_token_str = request.data.get('id_token')
        
        if not id_token_str:
            return JsonResponse({'error': 'ID Token is required'}, status=400)

        try:
            # Verify the ID token with Google
            idinfo = id_token.verify_oauth2_token(id_token_str, Request(), settings.SOCIAL_AUTH_GOOGLE_OAUTH2_KEY)
            
            # ID token verification passed, check the user's email or other data
            email = idinfo.get('email')
            if email is None:
                return JsonResponse({'error': 'Invalid ID Token'}, status=400)
            
            picture_url = idinfo.get('picture')
            # Find or create the user in your database (you can use email to find the user)
            user, created = CustomUser.objects.get_or_create(
                email=email,
                defaults={
                    'first_name': idinfo.get('given_name', 'Google'),
                    'last_name': idinfo.get('family_name', ''),
                    'is_verified': True,
                    'is_active': True,
                    'auth_provider': 'google',
                    'profile_picture':picture_url
                }
            )
            

            if picture_url and user.profile_picture != picture_url:
                user.profile_picture = picture_url
                user.save()
            # Create JWT token (access + refresh)
            refresh = RefreshToken.for_user(user)
            
            # Return tokens and user data to frontend
            return JsonResponse({
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh),
                'email': user.email,
                'full_name': user.get_full_name(),
                'profile_picture': user.profile_picture,
                'message': 'Google authentication successful'
            }, status=200)

        except ValueError:
            # Raised if the token is invalid
            return JsonResponse({'error': 'Invalid ID token'}, status=400)



User=get_user_model()
class facebookLoginView(GenericAPIView):
    serializer_class = FacebookLoginSerializer


    def post(self,request,*args,**kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        access_token = serializer.validated_data.get('access_token')


        fb_response = requests.get(
            'https://graph.facebook.com/me',
            params={
                'fields':'id,name,email',
                'access_token':access_token
            }
        )
        if fb_response.status_code != 200:
            return Response({'error':'invalid facebook token'},status=status.HTTP_400_BAD_REQUEST)
        

        fb_data = fb_response.json()

        email = fb_data.get('email')

        name = fb_data.get('name','')

        user_id = fb_data.get('id')

        if not email:
            return Response({'error':'facebook account must provide an email'},status=status.HTTP_400_BAD_REQUEST)
        
        first_name = name.split(' ')[0]

        last_name = ' '.join(name.split(' ')[1:]) if len (name.split(' ')) > 1 else ''

        pic_response = requests.get(
            f"https://graph.facebook.com/v19.0/{user_id}/picture",
            params={
                "access_token":access_token,
                "redirect":False,
                "type":"large",

            }
        )
        profile_picture=None
        if pic_response.status_code == 200:
            profile_picture = pic_response.json().get("data", {}).get("url")

        user, created =User.objects.get_or_create(email=email,defaults={
            'first_name':first_name,
            'last_name':last_name,
            'is_verified':True,
            'is_active':True,
            'auth_provider':'facebook',
            'profile_picture':profile_picture
        })

        if not created:
            user.first_name = first_name
            user.last_name = last_name
            user.auth_procider = 'facebook'
            if profile_picture:
                user.profile_picture = profile_picture
            user.save()
        refresh = RefreshToken.for_user(user)

        return Response({
            'access_token':str(refresh.access_token),
            'refresh_token':str(refresh),
            'email':user.email,
            'full_name':f"{user.get_full_name()}",
            'profile_picture': user.profile_picture
        },status=status.HTTP_200_OK)