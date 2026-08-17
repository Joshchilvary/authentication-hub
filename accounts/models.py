"""
Custom user model for the authentication hub.

This model extends Django's AbstractUser to support authentication via email
instead of the default username field, while retaining all built-in
authentication features such as permissions, groups, and session management.
"""

from django.db import models
from django.contrib.auth.models import AbstractUser

from .managers import UserManager


class User(AbstractUser):
    """
    Custom user model that extends AbstractUser for email-based authentication.

    Uses email as the unique identifier instead of the default username field,
    while preserving all default Django authentication functionality.
    """

    username = None
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=20, blank=True, verbose_name="Phone Number")
    profile_picture = models.ImageField(upload_to="users/profile_pictures/", blank=True, null=True, verbose_name="Profile Picture")
    bio = models.TextField(blank=True, verbose_name="Biography")
    is_verified = models.BooleanField(default=False, verbose_name="Email Verified")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created At")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Updated At")

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
        ordering = ["-created_at"]

    def __str__(self):
        return self.email


class LoginHistory(models.Model):
    """
    Audit record for authentication-related events.

    Stores successful and failed login attempts, logouts, and session
    expirations. IP addresses and user-agent strings are captured as
    security/audit data. The user relationship is nullable because
    failed login attempts may involve emails that do not belong to
    an existing account.
    """

    EVENT_TYPE_LOGIN_SUCCESS = 'login_success'
    EVENT_TYPE_LOGIN_FAILED = 'login_failed'
    EVENT_TYPE_LOGIN_THROTTLED = 'login_throttled'
    EVENT_TYPE_LOGIN_BLOCKED = 'login_blocked'
    EVENT_TYPE_LOGOUT = 'logout'
    EVENT_TYPE_SESSION_EXPIRED = 'session_expired'
    EVENT_TYPE_PASSWORD_CHANGE = 'password_change'
    EVENT_TYPE_PASSWORD_RESET_REQUEST = 'password_reset_request'
    EVENT_TYPE_PASSWORD_RESET_COMPLETED = 'password_reset_completed'
    EVENT_TYPE_EMERGENCY_SECURITY_ACTION = 'emergency_security_action'

    EVENT_TYPE_CHOICES = [
        (EVENT_TYPE_LOGIN_SUCCESS, 'Login Success'),
        (EVENT_TYPE_LOGIN_FAILED, 'Login Failed'),
        (EVENT_TYPE_LOGIN_THROTTLED, 'Login Throttled'),
        (EVENT_TYPE_LOGIN_BLOCKED, 'Login Blocked'),
        (EVENT_TYPE_LOGOUT, 'Logout'),
        (EVENT_TYPE_SESSION_EXPIRED, 'Session Expired'),
        (EVENT_TYPE_PASSWORD_CHANGE, 'Password Change'),
        (EVENT_TYPE_PASSWORD_RESET_REQUEST, 'Password Reset Request'),
        (EVENT_TYPE_PASSWORD_RESET_COMPLETED, 'Password Reset Completed'),
        (EVENT_TYPE_EMERGENCY_SECURITY_ACTION, 'Emergency Security Action'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='login_history',
        verbose_name='User',
    )
    email_attempted = models.EmailField(max_length=254, verbose_name='Email Attempted')
    ip_address = models.GenericIPAddressField(null=True, blank=True, verbose_name='IP Address')
    user_agent = models.TextField(blank=True, verbose_name='User Agent')
    browser = models.CharField(max_length=100, blank=True, verbose_name='Browser')
    operating_system = models.CharField(max_length=100, blank=True, verbose_name='Operating System')
    device_info = models.CharField(max_length=100, blank=True, verbose_name='Device')
    new_device = models.BooleanField(default=False, verbose_name='New Device')
    event_type = models.CharField(max_length=30, choices=EVENT_TYPE_CHOICES, verbose_name='Event Type')
    timestamp = models.DateTimeField(auto_now_add=True, verbose_name='Timestamp')
    session_key = models.CharField(max_length=40, null=True, blank=True, verbose_name='Session Key')

    class Meta:
        verbose_name = 'Login History'
        verbose_name_plural = 'Login History'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['email_attempted']),
            models.Index(fields=['event_type']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['ip_address']),
        ]

    def __str__(self):
        return f"{self.email_attempted} - {self.get_event_type_display()} - {self.timestamp}"


class UserSession(models.Model):
    """
    Represents an authenticated session for a user.

    Tracks active sessions across devices so users can review
    and manage their authenticated sessions. Linked to Django's
    session framework via session_key but stored separately for
    efficient querying and user-scoped access control.
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='user_sessions',
        verbose_name='User',
    )
    session_key = models.CharField(
        max_length=40,
        unique=True,
        verbose_name='Session Key',
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name='IP Address',
    )
    user_agent = models.TextField(blank=True, verbose_name='User Agent')
    browser = models.CharField(max_length=100, blank=True, verbose_name='Browser')
    operating_system = models.CharField(max_length=100, blank=True, verbose_name='Operating System')
    device_info = models.CharField(max_length=100, blank=True, verbose_name='Device')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Created At')
    last_activity = models.DateTimeField(verbose_name='Last Activity')
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name='Expires At',
    )
    remember_me = models.BooleanField(default=False, verbose_name='Remember Me')
    is_active = models.BooleanField(default=True, verbose_name='Active')

    class Meta:
        verbose_name = 'User Session'
        verbose_name_plural = 'User Sessions'
        ordering = ['-last_activity']
        indexes = [
            models.Index(fields=['user', 'is_active']),
            models.Index(fields=['expires_at']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.browser} - {self.device_info}"


class SecurityNotification(models.Model):
    """
    Security-related notification for a user.

    Stores important authentication and account security events
    so users can review their security history from a single place.
    """

    NOTIFICATION_TYPE_NEW_LOGIN = 'new_login'
    NOTIFICATION_TYPE_NEW_DEVICE_LOGIN = 'new_device_login'
    NOTIFICATION_TYPE_MULTIPLE_FAILED_LOGINS = 'multiple_failed_logins'
    NOTIFICATION_TYPE_ACCOUNT_LOCKED = 'account_locked'
    NOTIFICATION_TYPE_PASSWORD_CHANGED = 'password_changed'
    NOTIFICATION_TYPE_PASSWORD_RESET = 'password_reset'
    NOTIFICATION_TYPE_SESSION_EXPIRED = 'session_expired'
    NOTIFICATION_TYPE_OTHER_SESSIONS_LOGGED_OUT = 'other_sessions_logged_out'
    NOTIFICATION_TYPE_EMAIL_VERIFIED = 'email_verified'
    NOTIFICATION_TYPE_EMERGENCY_SECURITY_ACTION = 'emergency_security_action'

    NOTIFICATION_TYPE_CHOICES = [
        (NOTIFICATION_TYPE_NEW_LOGIN, 'New Login'),
        (NOTIFICATION_TYPE_NEW_DEVICE_LOGIN, 'New Device Login'),
        (NOTIFICATION_TYPE_MULTIPLE_FAILED_LOGINS, 'Multiple Failed Logins'),
        (NOTIFICATION_TYPE_ACCOUNT_LOCKED, 'Account Locked'),
        (NOTIFICATION_TYPE_PASSWORD_CHANGED, 'Password Changed'),
        (NOTIFICATION_TYPE_PASSWORD_RESET, 'Password Reset'),
        (NOTIFICATION_TYPE_SESSION_EXPIRED, 'Session Expired'),
        (NOTIFICATION_TYPE_OTHER_SESSIONS_LOGGED_OUT, 'Other Sessions Logged Out'),
        (NOTIFICATION_TYPE_EMAIL_VERIFIED, 'Email Verified'),
        (NOTIFICATION_TYPE_EMERGENCY_SECURITY_ACTION, 'Emergency Security Action'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='security_notifications',
        verbose_name='User',
    )
    notification_type = models.CharField(max_length=30, choices=NOTIFICATION_TYPE_CHOICES, verbose_name='Notification Type')
    title = models.CharField(max_length=200, verbose_name='Title')
    message = models.TextField(verbose_name='Message')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Created At')
    is_read = models.BooleanField(default=False, verbose_name='Read')
    ip_address = models.GenericIPAddressField(null=True, blank=True, verbose_name='IP Address')
    browser = models.CharField(max_length=100, blank=True, verbose_name='Browser')
    operating_system = models.CharField(max_length=100, blank=True, verbose_name='Operating System')
    device_info = models.CharField(max_length=100, blank=True, verbose_name='Device')
    session_key = models.CharField(max_length=40, blank=True, verbose_name='Session Key')

    class Meta:
        verbose_name = 'Security Notification'
        verbose_name_plural = 'Security Notifications'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'is_read']),
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['notification_type']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.get_notification_type_display()} - {self.created_at}"


class SecurityRiskAssessment(models.Model):
    """
    Records a security risk assessment for a login event.

    Stores the calculated risk score, level, and human-readable reasons
    so that users and administrators can review unusual authentication
    activity.
    """

    RISK_LEVEL_LOW = 'low'
    RISK_LEVEL_MEDIUM = 'medium'
    RISK_LEVEL_HIGH = 'high'
    RISK_LEVEL_CRITICAL = 'critical'

    RISK_LEVEL_CHOICES = [
        (RISK_LEVEL_LOW, 'Low'),
        (RISK_LEVEL_MEDIUM, 'Medium'),
        (RISK_LEVEL_HIGH, 'High'),
        (RISK_LEVEL_CRITICAL, 'Critical'),
    ]

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='risk_assessments',
        verbose_name='User',
    )
    login_history = models.ForeignKey(
        LoginHistory,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='risk_assessments',
        verbose_name='Login History',
    )
    ip_address = models.GenericIPAddressField(null=True, blank=True, verbose_name='IP Address')
    browser = models.CharField(max_length=100, blank=True, verbose_name='Browser')
    operating_system = models.CharField(max_length=100, blank=True, verbose_name='Operating System')
    device_info = models.CharField(max_length=100, blank=True, verbose_name='Device')
    risk_score = models.PositiveSmallIntegerField(default=0, verbose_name='Risk Score')
    risk_level = models.CharField(max_length=20, choices=RISK_LEVEL_CHOICES, default=RISK_LEVEL_LOW, verbose_name='Risk Level')
    risk_reasons = models.TextField(blank=True, verbose_name='Risk Reasons')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Created At')
    session_key = models.CharField(max_length=40, blank=True, verbose_name='Session Key')

    class Meta:
        verbose_name = 'Security Risk Assessment'
        verbose_name_plural = 'Security Risk Assessments'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['risk_level']),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.risk_level} ({self.risk_score}) - {self.created_at}"


class LoginAttempt(models.Model):
    """
    Tracks failed login attempts for brute-force protection.

    Maintains separate counters for email-based and IP-based throttling.
    A record with a blank email represents IP-only tracking.
    A record with a blank IP represents email-only tracking.
    """

    email = models.EmailField(blank=True, verbose_name='Email')
    ip_address = models.GenericIPAddressField(null=True, blank=True, verbose_name='IP Address')
    failed_attempts = models.PositiveIntegerField(default=0, verbose_name='Failed Attempts')
    first_attempt_at = models.DateTimeField(auto_now_add=True, verbose_name='First Attempt At')
    last_attempt_at = models.DateTimeField(auto_now=True, verbose_name='Last Attempt At')
    blocked_until = models.DateTimeField(null=True, blank=True, verbose_name='Blocked Until')

    class Meta:
        verbose_name = 'Login Attempt'
        verbose_name_plural = 'Login Attempts'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['last_attempt_at']),
            models.Index(fields=['blocked_until']),
        ]

    def __str__(self):
        return f"{self.email or self.ip_address} - {self.failed_attempts} attempts"
