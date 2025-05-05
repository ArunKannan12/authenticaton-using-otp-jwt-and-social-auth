from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import AuthenticationFailed
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

    class Meta:
        model=CustomUser
        fields=['email','password1','full_name','access_token','refresh_token']
    
    def validate(self, attrs):
        email=attrs.get('email')
        password1=attrs.get('password1')

        user=authenticate(request=self.context.get('request'),email=email,password=password1)

        if not user:
            raise AuthenticationFailed('account not activated')
        

        if not user.is_verified:
            raise AuthenticationFailed('email is not verified')
        user_tokens=user.tokens()

        return {
            'email': user.email,
            'full_name': user.get_full_name,  # Ensure you call get_full_name()
            'access_token': str(user_tokens.get('access')),
            'refresh_token': str(user_tokens.get('refresh'))
        }