from django.urls import reverse
from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth import authenticate
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.utils.encoding import force_str
from django.contrib.sites.shortcuts import get_current_site
from .utils import send_normal_email
from django.utils.encoding import force_bytes


class UserRegisterSerializer(serializers.ModelSerializer):
    password1=serializers.CharField(max_length=68,min_length=6,write_only=True)
    password2=serializers.CharField(max_length=68,min_length=6,write_only=True)
    class Meta:
        model=CustomUser
        fields=['email','first_name','last_name','password1','password2']


    def validate(self, attrs):
        password1=attrs.get('password1')
        password2=attrs.get('password2')
        if password1 != password2:
            raise serializers.ValidationError("Password do not match")
        return attrs
        
    
    def create(self, validated_data):
        validated_data.pop('password2')  # Not needed anymore
        password = validated_data.pop('password1')

        user = CustomUser.objects.create_user(
            password=password,
            **validated_data
        )
        return user
    



class LoginSerializer(serializers.Serializer):
    email=serializers.EmailField()
    password1=serializers.CharField(write_only=True)
    full_name=serializers.CharField(max_length=255,read_only=True)
    access_token=serializers.CharField(max_length=255,read_only=True)
    refresh_token=serializers.CharField(max_length=255,read_only=True)

    
    def validate(self, attrs):
        email=attrs.get('email')
        password1=attrs.get('password1')
        try:
            user_obj = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise AuthenticationFailed('Account does not exist')

        if not user_obj.check_password(password1):
            raise AuthenticationFailed('Incorrect password')

        if not user_obj.is_verified:
            raise AuthenticationFailed('Email is not verified')

        user_tokens = user_obj.tokens()
        
        return {
            'email':user_obj.email,
            'full_name': user_obj.get_full_name,  # Ensure you call get_full_name()
            'access_token': str(user_tokens.get('access')),
            'refresh_token': str(user_tokens.get('refresh'))
        }
    

class PasswordResetRequestSerializer(serializers.Serializer):
    email=serializers.EmailField(max_length=255)

    

    def validate_email(self,value):
        request=self.context.get('request')
        email=value

        if CustomUser.objects.filter(email=email).exists():
            user=CustomUser.objects.get(email=email)

            uidb64 = urlsafe_base64_encode(force_bytes(user.id))
            token=PasswordResetTokenGenerator().make_token(user)
            site_domain=get_current_site(request).domain
            
            relative_link=reverse('password-reset-confirm',kwargs={'uidb64':uidb64,'token':token})
            abslink=f"http://{site_domain}{relative_link}"

            email_body=f"hi {user.email },\n\ use the link to reset you password \n {abslink}"
            data={
                'email_body':email_body,
                'email_subject':'reset your password',
                'to_email':user.email
            }
            send_normal_email(data)




        return value



class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=100, min_length=6, write_only=True)
    confirm_password = serializers.CharField(max_length=100, min_length=6, write_only=True)
    uidb64 = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        uidb64 = attrs.get('uidb64')
        token = attrs.get('token')

        if password != confirm_password:
            raise serializers.ValidationError("Passwords do not match.")

        try:
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(id=user_id)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            raise serializers.ValidationError("Invalid user.")

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("Token is invalid or expired.")

        # ✅ Set and save new password
        user.set_password(password)
        user.save()

        return attrs
