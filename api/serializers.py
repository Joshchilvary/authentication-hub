from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.models import update_last_login
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils import timezone

from accounts.models import LoginHistory, UserSession, SecurityNotification, SecurityRiskAssessment
from accounts.forms import ALLOWED_EXTENSIONS, MAX_FILE_SIZE
from accounts.utils import (
    get_client_ip,
    parse_user_agent,
    is_login_blocked,
    record_failed_attempt,
    reset_failed_attempts,
    create_security_notification,
    calculate_login_risk_score,
    create_security_risk_assessment,
)
import os

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """
    Safe read-only serializer for the User model.

    Exposes only non-sensitive user information.
    Never includes passwords, session keys, tokens, or security internals.
    """

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "phone_number",
            "bio",
            "profile_picture",
            "is_verified",
            "created_at",
        ]
        read_only_fields = [
            "id",
            "email",
            "is_verified",
            "created_at",
        ]


class SafeUserSerializer(serializers.ModelSerializer):
    """
    Minimal safe serializer for including user data in token responses.
    """

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "is_verified",
        ]
        read_only_fields = fields


class UserProfileSerializer(serializers.ModelSerializer):
    """
    Safe writable serializer for the User model.

    Allows updating only safe profile fields.
    Never allows updates to email, password, is_staff, is_superuser,
    is_verified, or other security-sensitive fields.
    """
    FORBIDDEN_FIELDS = {
        "email",
        "password",
        "is_staff",
        "is_superuser",
        "is_verified",
        "username",
        "last_login",
        "date_joined",
        "created_at",
        "updated_at",
        "groups",
        "user_permissions",
    }
    profile_picture = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "phone_number",
            "bio",
            "profile_picture",
        ]
        read_only_fields = [
            "id",
        ]

    def validate(self, attrs):
        """
        Reject attempts to update forbidden fields.
        """
        forbidden = self.FORBIDDEN_FIELDS.intersection(self.initial_data.keys())
        if forbidden:
            raise serializers.ValidationError(
                f"The following fields cannot be updated via the API: {', '.join(sorted(forbidden))}."
            )
        return attrs

    def validate_profile_picture(self, value):
        """
        Validate the uploaded profile picture.

        Reuses the existing project validation rules:
        - Only jpg, jpeg, png, and webp extensions are allowed.
        - Maximum file size is 2 MB.
        """
        if not value:
            return self.instance.profile_picture if self.instance else value

        ext = os.path.splitext(value.name)[1].lower().lstrip(".")
        if ext not in ALLOWED_EXTENSIONS:
            raise serializers.ValidationError(
                "Only JPG, JPEG, PNG, and WebP files are allowed."
            )

        if value.size > MAX_FILE_SIZE:
            raise serializers.ValidationError(
                "The uploaded file exceeds the 2 MB size limit."
            )

        return value


class LoginHistorySerializer(serializers.ModelSerializer):
    """
    Safe serializer for LoginHistory.

    Exposes audit information without internal session data.
    """

    class Meta:
        model = LoginHistory
        fields = [
            "id",
            "event_type",
            "timestamp",
            "ip_address",
            "browser",
            "operating_system",
            "device_info",
            "new_device",
        ]
        read_only_fields = fields


class UserSessionSerializer(serializers.ModelSerializer):
    """
    Safe serializer for UserSession.

    Never exposes the actual session_key.
    Indicates whether the session is the current active session.
    """
    is_current_session = serializers.SerializerMethodField()

    class Meta:
        model = UserSession
        fields = [
            "id",
            "browser",
            "operating_system",
            "device_info",
            "ip_address",
            "created_at",
            "last_activity",
            "expires_at",
            "is_active",
            "remember_me",
            "is_current_session",
        ]
        read_only_fields = fields

    def get_is_current_session(self, obj):
        request = self.context.get("request")
        if not request or not hasattr(request, "session"):
            return False
        return obj.session_key == request.session.session_key


class SecurityNotificationSerializer(serializers.ModelSerializer):
    """
    Safe serializer for SecurityNotification.
    """

    class Meta:
        model = SecurityNotification
        fields = [
            "id",
            "notification_type",
            "title",
            "message",
            "is_read",
            "created_at",
        ]
        read_only_fields = fields


class SecurityRiskAssessmentSerializer(serializers.ModelSerializer):
    """
    Safe serializer for SecurityRiskAssessment.
    """

    class Meta:
        model = SecurityRiskAssessment
        fields = [
            "id",
            "risk_score",
            "risk_level",
            "risk_reasons",
            "created_at",
        ]
        read_only_fields = fields


class CustomTokenObtainPairSerializer(serializers.Serializer):
    """
    Custom JWT token serializer for email-based authentication.

    Accepts 'email' and 'password' fields explicitly.
    """
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True, style={"input_type": "password"})

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = None

    def validate(self, attrs):
        email = attrs.get("email", "").strip().lower()
        password = attrs.get("password", "")
        request = self.context.get("request")

        self.user = authenticate(
            request=request,
            email=email,
            password=password,
        )

        if not self.user or not self.user.is_active:
            raise serializers.ValidationError(
                "No active account found with the given credentials."
            )

        return {
            "email": email,
            "password": password,
        }


class CustomTokenObtainPairResponseSerializer(serializers.Serializer):
    """
    Custom response serializer for JWT token generation.
    """
    access = serializers.CharField()
    refresh = serializers.CharField()
    user = SafeUserSerializer()


def _record_failed_login_history_api(request, email, ip_address, user_agent_string, parsed_ua, user=None):
    """
    Record a failed API login event in LoginHistory.

    This is a standalone helper for the JWT endpoint that does not
    depend on Django form data.
    """
    try:
        LoginHistory.objects.create(
            user=user,
            email_attempted=email,
            ip_address=ip_address,
            user_agent=user_agent_string,
            browser=parsed_ua.get("browser", ""),
            operating_system=parsed_ua.get("operating_system", ""),
            device_info=parsed_ua.get("device_info", ""),
            event_type=LoginHistory.EVENT_TYPE_LOGIN_FAILED,
        )
    except Exception:
        import logging
        logger = logging.getLogger(__name__)
        logger.exception("Failed to record failed API login history")


def _record_login_history_api(request, user, email, ip_address, user_agent_string, parsed_ua):
    """
    Record a successful API login event in LoginHistory and trigger
    security notifications and risk assessment.
    """
    try:
        new_device = False
        if user.pk:
            matching_sessions = UserSession.objects.filter(
                user=user,
                browser=parsed_ua.get("browser", ""),
                operating_system=parsed_ua.get("operating_system", ""),
                device_info=parsed_ua.get("device_info", ""),
            )
            if not matching_sessions.exists():
                new_device = True

        login_history = LoginHistory.objects.create(
            user=user,
            email_attempted=email,
            ip_address=ip_address,
            user_agent=user_agent_string,
            browser=parsed_ua.get("browser", ""),
            operating_system=parsed_ua.get("operating_system", ""),
            device_info=parsed_ua.get("device_info", ""),
            new_device=new_device,
            event_type=LoginHistory.EVENT_TYPE_LOGIN_SUCCESS,
        )

        notification_type = (
            SecurityNotification.NOTIFICATION_TYPE_NEW_DEVICE_LOGIN
            if new_device
            else SecurityNotification.NOTIFICATION_TYPE_NEW_LOGIN
        )
        create_security_notification(
            user=user,
            notification_type=notification_type,
            title="New login detected" if not new_device else "New device login detected",
            message=(
                f"A new login was detected on your account from "
                f"{parsed_ua.get('browser', '')} on {parsed_ua.get('operating_system', '')} "
                f"({parsed_ua.get('device_info', '')})."
            ),
            request=request,
        )

        if new_device:
            try:
                current_site = get_current_site(request)
                context = {
                    "user": user,
                    "domain": current_site.domain,
                    "timestamp": timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "browser": parsed_ua.get("browser", ""),
                    "operating_system": parsed_ua.get("operating_system", ""),
                    "device_info": parsed_ua.get("device_info", ""),
                    "ip_address": ip_address,
                }
                subject = "New login detected"
                plain_message = render_to_string("accounts/emails/new_login_notification.txt", context)
                html_message = render_to_string("accounts/emails/new_login_notification.html", context)

                send_mail(
                    subject=subject,
                    message=plain_message,
                    from_email=None,
                    recipient_list=[user.email],
                    html_message=html_message,
                )
            except Exception:
                import logging
                logger = logging.getLogger(__name__)
                logger.exception("Failed to send new login notification email")

        create_security_risk_assessment(
            user=user,
            login_history=login_history,
            ip_address=ip_address,
            browser=parsed_ua.get("browser", ""),
            operating_system=parsed_ua.get("operating_system", ""),
            device_info=parsed_ua.get("device_info", ""),
        )
    except Exception:
        import logging
        logger = logging.getLogger(__name__)
        logger.exception("Failed to record API login history")
