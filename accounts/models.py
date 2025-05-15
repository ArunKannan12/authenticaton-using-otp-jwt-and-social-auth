from django.db import models
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.tokens import RefreshToken
import pyotp
from django.utils import timezone

AUTH_PROVIDERS = {
    'email': 'Email',
    'google': 'Google',
    'facebook': 'Facebook',
    'github': 'GitHub',
}

class CustomUserManager(BaseUserManager):
    def email_validator(self, email):
        try:
            validate_email(email)
        except ValidationError:
            raise ValueError(_("Please enter a valid email address"))

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError(_("Email is required"))

        self.email_validator(email)
        email = self.normalize_email(email)

        first_name = extra_fields.get('first_name') or 'User'
        last_name = extra_fields.get('last_name') or ''

        extra_fields['first_name'] = first_name
        extra_fields['last_name'] = last_name

        extra_fields.setdefault('secret_key',pyotp.random_base32())
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if not password:
            raise ValueError(_("Superusers must have a password."))

        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))

        return self.create_user(email, password, **extra_fields)

def user_profile_upload_path(instance, filename):
    return f'profile_pics/{instance.email}/{filename}'

class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(max_length=254, unique=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    secret_key = models.CharField(max_length=32, blank=True,null=True)
    otp_expiry = models.DateTimeField(blank=True, null=True)
    profile_picture = models.URLField(blank=True,null=True)
    custom_user_profile=models.ImageField( upload_to=user_profile_upload_path,blank=True,null=True)


    auth_provider=models.CharField( max_length=50,default=AUTH_PROVIDERS.get("email"))

    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = CustomUserManager()

    def __str__(self):
        return self.first_name

    
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }

    def is_otp_valid(self):
        if not self.otp_expiry:
            return False
        return timezone.now() < self.otp_expiry

class OneTimePassword(models.Model):
    user=models.OneToOneField(CustomUser,on_delete=models.CASCADE)
    code=models.CharField( max_length=6,unique=True)


    def __str__(self):
        return f"{self.user.first_name}-passcode"