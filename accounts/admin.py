from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.translation import gettext_lazy as _
from .models import CustomUser

@admin.register(CustomUser)
class CustomUserAdmin(BaseUserAdmin):
    model = CustomUser
    list_display = (
        'email', 'first_name', 'last_name', 'is_verified',
        'is_active', 'is_staff', 'is_superuser',
        'block_count', 'blocked_until', 'is_permanently_banned',
        'date_joined', 'last_login'
    )
    list_filter = (
        'is_verified', 'is_active', 'is_staff', 'is_superuser', 'is_permanently_banned'
    )
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('-date_joined',)

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal Info'), {'fields': ('first_name', 'last_name', 'profile_picture', 'custom_user_profile')}),
        (_('Verification'), {'fields': ('is_verified', 'secret_key', 'otp_expiry')}),
        (_('Permissions'), {
            'fields': (
                'is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions',
            )
        }),
        (_('Security'), {'fields': ('block_count', 'blocked_until', 'is_permanently_banned')}),
        (_('Important Dates'), {'fields': ('last_login', 'date_joined')}),
        (_('Other'), {'fields': ('auth_provider',)}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'password1', 'password2', 'is_active', 'is_staff', 'is_superuser'),
        }),
    )
