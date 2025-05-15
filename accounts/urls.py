
from django.urls import path,include
from .views import (
    RegisterUserView,
    SendOTPView,
    VerifyOTPView,
    LoginUserView,
    passwordResetConfirm,
    PasswordResetRequestView,
    SetNewPasswordView,
    LogoutUserView,
    GoogleAuthView,
    ProfileView,
    facebookLoginView
    
  
)

from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/',RegisterUserView.as_view(),name='register'),
    path('send-otp/', SendOTPView.as_view(), name='send_otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('login/',LoginUserView.as_view(),name='login'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('token/refresh/',TokenRefreshView.as_view(),name='refresh_token'),
    path('password-reset/',PasswordResetRequestView.as_view(),name='password-reset'),
    path('password-reset-confirm/<uidb64>/<token>/',passwordResetConfirm.as_view(),name='password-reset-confirm'),
    path('set-new-password/', SetNewPasswordView.as_view(), name='set-new-password'),
    path('logout/', LogoutUserView.as_view(), name='logout'),

    path('social-login/', GoogleAuthView.as_view(), name='google'),
    path("facebook/", facebookLoginView.as_view(), name="facebook"),
    path('google/', include('social_django.urls', namespace='social-login')),


]
