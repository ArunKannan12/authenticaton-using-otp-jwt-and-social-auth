# utils.py
import pyotp
from django.core.mail import send_mail
from django.conf import settings
from datetime import timedelta
from django.utils import timezone

def send_otp_via_email(user):
    if not user.secret_key:
        user.secret_key = pyotp.random_base32()

    totp = pyotp.TOTP(user.secret_key,interval=60)
    otp = totp.now()

    user.otp_expiry = timezone.now() + timedelta(minutes=5)
    user.save()

    subject = "Your OTP Code"
    message = f"Hi {user.first_name}, your OTP code is: {otp}"
    from_email = settings.DEFAULT_FROM_EMAIL
    recipient_list = [user.email]

    send_mail(subject, message, from_email, recipient_list)
