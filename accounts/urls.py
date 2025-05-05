from django.urls import path
from .views import RegisterUserView,SendOTPView,VerifyOTPView,LoginUserView
urlpatterns = [
    path('register/',RegisterUserView.as_view(),name='register'),
    path('send-otp/', SendOTPView.as_view(), name='send_otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('login/',LoginUserView.as_view(),name='login'),

]
