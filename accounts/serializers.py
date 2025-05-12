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
from rest_framework_simplejwt.tokens import RefreshToken,Token
from rest_framework_simplejwt.exceptions import TokenError,InvalidToken
from rest_framework.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError


class UserRegisterSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(max_length=68, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=68, min_length=6, write_only=True)

    class Meta:
        model = CustomUser
        fields = ['email', 'first_name', 'last_name', 'password1', 'password2']

    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already registered.")
        return value

    def validate(self, attrs):
        password1 = attrs.get('password1')
        password2 = attrs.get('password2')

        if password1 != password2:
            raise serializers.ValidationError({"password2": "Passwords do not match."})

        # Optional: Use Django's password validators
        try:
            validate_password(password1)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"password1": list(e.messages)})

        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        password = validated_data.pop('password1')
        user = CustomUser.objects.create_user(password=password, **validated_data)
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

            'email': user_obj.email,
            'message': f"Welcome {user_obj.first_name} {user_obj.last_name}",
            'first_name': user_obj.first_name,
            'last_name': user_obj.last_name,
            'full_name': user_obj.get_full_name(),   # Ensure you call get_full_name() method here
            'email':user_obj.email,

            'access_token': str(user_tokens.get('access')),
            'refresh_token': str(user_tokens.get('refresh'))
        }
    

class PasswordResetRequestSerializer(serializers.Serializer):
    email=serializers.EmailField(max_length=255)

    

    def validate_email(self,value):
        request=self.context.get('request')
        email=value

        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("No account found with this email.")
        

        if not user.is_verified:
            raise serializers.ValidationError('no account found with this email')
        

        if user.auth_provider == 'google':
            raise serializers.ValidationError("You cannot reset your password because you logged in via Google. Please use Google login.")

        uidb64 = urlsafe_base64_encode(force_bytes(user.id))
        token=PasswordResetTokenGenerator().make_token(user)
        site_domain=get_current_site(request).domain
        
        relative_link=reverse('password-reset-confirm',kwargs={'uidb64':uidb64,'token':token})
        abslink=f"http://{site_domain}{relative_link}"

        email_body=f"hi {user.email },\n use the link to reset you password \n {abslink}"

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

            # Decode the UID and get the user object
            user_id = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(id=user_id)
        except (TypeError, ValueError, OverflowError) as e:
            # Handle decoding or invalid ID error
            raise serializers.ValidationError("Invalid user. Error: {}".format(str(e)))
        except CustomUser.DoesNotExist:
            # Handle the case where the user does not exist in the database
            raise serializers.ValidationError("User not found.")
        except Exception as e:
            # Catch any other unforeseen errors
            raise serializers.ValidationError("An unexpected error occurred: {}".format(str(e)))

        # Validate the token
        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError("Token is invalid or expired.")

        try:
            # Set and save the new password
            user.set_password(password)
            user.save()
        except Exception as e:
            # Handle any errors when setting or saving the password
            raise serializers.ValidationError("An error occurred while saving the password: {}".format(str(e)))

        return attrs


class LogoutuserSerializer(serializers.Serializer):
    refresh=serializers.CharField()
    default_error_messages={
        'bad_token':('token is invalid or has expired')
    }


    def validate(self, attrs):
        self.token=attrs.get('refresh').strip()
        return super().validate(attrs)
    

    def save(self,**kwargs):
        try:
            token=RefreshToken(self.token)
            token.blacklist()
        except (InvalidToken,TokenError):
            print("Refresh token invalid or already blacklisted.")
        except Exception as e:
            raise ValidationError({'non_field_errors': [f"Unexpected error: {str(e)}"]})
        

class CustomUserSerializer(serializers.ModelSerializer):
    full_name=serializers.SerializerMethodField()
    class Meta:
        model=CustomUser
        fields = [
            'id',
            'email',
            'first_name',
            'last_name',
            'full_name',
            'is_verified',
            'is_active',
            'auth_provider',
        ]
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}"

