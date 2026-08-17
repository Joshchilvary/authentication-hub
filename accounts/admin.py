"""
Django admin configuration for the custom User model.

Registers the User model with a custom UserAdmin subclass that provides
enhanced display, search, and filtering capabilities in the Django admin.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .forms import UserAdminChangeForm, UserAdminCreationForm
from .models import User, LoginHistory, SecurityNotification, SecurityRiskAssessment, UserSession, LoginAttempt


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    """
    Custom admin interface for the User model.

    Extends Django's UserAdmin to include custom fields in the admin
    interface, provide search functionality, and enable filtering by
    verification and administrative status.
    """

    form = UserAdminChangeForm
    add_form = UserAdminCreationForm

    list_display = (
        "email",
        "first_name",
        "last_name",
        "is_verified",
        "is_active",
        "is_staff",
        "is_superuser",
        "created_at",
        "updated_at",
    )
    list_filter = (
        "is_verified",
        "is_active",
        "is_staff",
        "is_superuser",
        "groups",
    )
    search_fields = (
        "email",
        "first_name",
        "last_name",
        "phone_number",
        "bio",
    )
    ordering = ("email",)
    filter_horizontal = ("groups", "user_permissions")

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (
            "Personal Info",
            {
                "fields": (
                    "first_name",
                    "last_name",
                    "phone_number",
                    "profile_picture",
                    "bio",
                )
            },
        ),
        (
            "Permissions",
            {
                "fields": (
                    "is_verified",
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        (
            "Timestamps",
            {"fields": ("created_at", "updated_at"), "classes": ("collapse",)},
        ),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "password1",
                    "password2",
                    "is_verified",
                    "is_active",
                    "is_staff",
                    "is_superuser",
                ),
            },
        ),
    )

    readonly_fields = ("created_at", "updated_at")


@admin.register(SecurityNotification)
class SecurityNotificationAdmin(admin.ModelAdmin):
    """
    Admin interface for SecurityNotification records.

    Allows administrators to inspect security notifications sent to users.
    Sensitive fields such as session_key are read-only or excluded.
    """

    list_display = (
        'user',
        'notification_type',
        'title',
        'is_read',
        'ip_address',
        'browser',
        'operating_system',
        'device_info',
        'created_at',
    )
    list_filter = (
        'notification_type',
        'is_read',
        'user',
        'created_at',
    )
    search_fields = (
        'user__email',
        'title',
        'ip_address',
        'browser',
        'operating_system',
        'device_info',
    )
    ordering = ('-created_at',)
    readonly_fields = tuple(field.name for field in SecurityNotification._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(SecurityRiskAssessment)
class SecurityRiskAssessmentAdmin(admin.ModelAdmin):
    """
    Admin interface for SecurityRiskAssessment records.

    Allows administrators to inspect login risk assessments.
    """

    list_display = (
        'user',
        'risk_level',
        'risk_score',
        'ip_address',
        'browser',
        'operating_system',
        'device_info',
        'created_at',
    )
    list_filter = (
        'risk_level',
        'user',
        'created_at',
    )
    search_fields = (
        'user__email',
        'ip_address',
        'browser',
        'operating_system',
        'device_info',
        'risk_reasons',
    )
    ordering = ('-created_at',)
    readonly_fields = tuple(field.name for field in SecurityRiskAssessment._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(LoginHistory)
class LoginHistoryAdmin(admin.ModelAdmin):
    """
    Admin interface for LoginHistory audit records.

    Provides read-only access to authentication event logs. Administrators
    can view, search, and filter events, but cannot add, modify, or
    delete audit records through this interface.
    """

    list_display = (
        'user',
        'email_attempted',
        'event_type',
        'ip_address',
        'browser',
        'operating_system',
        'device_info',
        'new_device',
        'timestamp',
    )
    list_filter = (
        'event_type',
        'user',
        'new_device',
        'timestamp',
    )
    search_fields = (
        'email_attempted',
        'ip_address',
        'user__email',
    )
    ordering = ('-timestamp',)
    readonly_fields = tuple(field.name for field in LoginHistory._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(UserSession)
class UserSessionAdmin(admin.ModelAdmin):
    """
    Admin interface for UserSession records.

    Provides read-only inspection of active and historical user sessions.
    Administrators can view, search, and filter sessions, but cannot
    add, modify, or delete session records through this interface.
    Session keys are stored internally but never exposed in the admin UI.
    """

    list_display = (
        'user',
        'browser',
        'operating_system',
        'device_info',
        'ip_address',
        'remember_me',
        'is_active',
        'created_at',
        'last_activity',
        'expires_at',
    )
    list_filter = (
        'is_active',
        'remember_me',
        'browser',
        'operating_system',
        'created_at',
    )
    search_fields = (
        'user__email',
        'ip_address',
        'browser',
        'operating_system',
        'device_info',
    )
    ordering = ('-last_activity',)
    readonly_fields = tuple(field.name for field in UserSession._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    """
    Admin interface for LoginAttempt rate-limit records.

    Allows administrators to inspect blocked accounts and IPs.
    No add/change/delete permissions because these records are
    managed automatically by the authentication system.
    """

    list_display = (
        'email',
        'ip_address',
        'failed_attempts',
        'blocked_until',
        'first_attempt_at',
        'last_attempt_at',
    )
    list_filter = (
        'blocked_until',
        'first_attempt_at',
    )
    search_fields = (
        'email',
        'ip_address',
    )
    ordering = ('-last_attempt_at',)
    readonly_fields = tuple(field.name for field in LoginAttempt._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
