from django.shortcuts import render
from django.utils import timezone
from django.contrib.sessions.models import Session
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status

from rest_framework_simplejwt.tokens import RefreshToken

from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from api.pagination import CustomPagination
from api.serializers import (
    UserSerializer,
    UserProfileSerializer,
    LoginHistorySerializer,
    UserSessionSerializer,
    SecurityNotificationSerializer,
    SecurityRiskAssessmentSerializer,
    CustomTokenObtainPairSerializer,
    CustomTokenObtainPairResponseSerializer,
    SafeUserSerializer,
    _record_failed_login_history_api,
    _record_login_history_api,
)

from accounts.models import LoginHistory, UserSession, SecurityNotification, SecurityRiskAssessment
from accounts.utils import (
    create_security_notification,
    get_client_ip,
    parse_user_agent,
    is_login_blocked,
    record_failed_attempt,
    reset_failed_attempts,
    notify_account_locked,
)

User = get_user_model()

schema_view = get_schema_view(
    openapi.Info(
        title="Authentication Hub API",
        default_version="v1",
        description=(
            "A secure Django REST API for user authentication, profile management, "
            "login history, active sessions, security notifications, and risk assessments. "
            "All endpoints under `/api/v1/` require authentication unless noted as public. "
            "Authenticated requests use either Django session cookies or JWT access tokens."
        ),
        terms_of_service="https://www.example.com/terms/",
        contact=openapi.Contact(email="support@example.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=[AllowAny],
)


@api_view(["GET"])
@permission_classes([AllowAny])
def api_root(request):
    """
    API root endpoint.

    Returns basic API information and links to documentation.
    """
    return Response(
        {
            "success": True,
            "data": {
                "name": "Authentication Hub API",
                "version": "v1",
                "documentation": {
                    "schema": "/api/v1/schema/",
                    "swagger_ui": "/api/v1/docs/",
                    "redoc": "/api/v1/redoc/",
                },
                "resources": [
                    "/api/v1/health/",
                    "/api/v1/me/",
                    "/api/v1/profile/",
                    "/api/v1/login-history/",
                    "/api/v1/sessions/",
                    "/api/v1/notifications/",
                    "/api/v1/risk-assessments/",
                    "/api/v1/auth/token/",
                ],
            },
        },
        status=status.HTTP_200_OK,
    )


@api_view(["GET"])
@permission_classes([AllowAny])
def health_check(request):
    """
    Health check endpoint.

    Confirms the API is reachable without exposing sensitive internals.
    """
    return Response(
        {
            "success": True,
            "data": {
                "status": "ok",
                "service": "Authentication Hub API",
                "version": "v1",
                "timestamp": timezone.now().isoformat(),
            },
        },
        status=status.HTTP_200_OK,
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def current_user(request):
    """
    Returns the currently authenticated user's safe profile information.

    Requires session authentication.
    Never exposes passwords, session keys, or other sensitive fields.
    """
    serializer = UserSerializer(request.user)
    return Response(
        {
            "success": True,
            "data": serializer.data,
        },
        status=status.HTTP_200_OK,
    )


@api_view(["GET", "PATCH"])
@permission_classes([IsAuthenticated])
def profile(request):
    """
    Returns or updates the authenticated user's profile information.

    GET: Returns safe profile data.
    PATCH: Updates allowed profile fields for request.user only.
    """
    if request.method == "GET":
        serializer = UserSerializer(request.user)
        return Response(
            {
                "success": True,
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )

    if request.method == "PATCH":
        serializer = UserProfileSerializer(
            request.user,
            data=request.data,
            partial=True,
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {
                "success": True,
                "data": serializer.data,
            },
            status=status.HTTP_200_OK,
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def login_history(request):
    """
    Returns login history belonging only to the authenticated user.

    Paginated. Ordered newest first.
    """
    queryset = LoginHistory.objects.filter(user=request.user).order_by("-timestamp")
    paginator = CustomPagination()
    page = paginator.paginate_queryset(queryset, request)
    serializer = LoginHistorySerializer(page, many=True)
    return paginator.get_paginated_response(serializer.data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def active_sessions(request):
    """
    Returns active sessions belonging only to the authenticated user.

    Never exposes session keys.
    Indicates which session is the current one.
    """
    queryset = UserSession.objects.filter(user=request.user, is_active=True).order_by("-last_activity")
    paginator = CustomPagination()
    page = paginator.paginate_queryset(queryset, request)
    serializer = UserSessionSerializer(page, many=True, context={"request": request})
    return paginator.get_paginated_response(serializer.data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def notifications(request):
    """
    Returns security notifications belonging only to the authenticated user.

    Paginated. Ordered newest first.
    """
    queryset = SecurityNotification.objects.filter(user=request.user).order_by("-created_at")
    paginator = CustomPagination()
    page = paginator.paginate_queryset(queryset, request)
    serializer = SecurityNotificationSerializer(page, many=True)
    return paginator.get_paginated_response(serializer.data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def risk_assessments(request):
    """
    Returns security risk assessments belonging only to the authenticated user.

    Paginated. Ordered newest first.
    """
    queryset = SecurityRiskAssessment.objects.filter(user=request.user).order_by("-created_at")
    paginator = CustomPagination()
    page = paginator.paginate_queryset(queryset, request)
    serializer = SecurityRiskAssessmentSerializer(page, many=True)
    return paginator.get_paginated_response(serializer.data)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def mark_notification_read(request, notification_id):
    """
    Mark a single security notification as read.

    Requires the notification to belong to request.user.
    """
    notification = get_object_or_404(
        SecurityNotification,
        id=notification_id,
        user=request.user,
    )
    notification.is_read = True
    notification.save(update_fields=["is_read"])

    return Response(
        {
            "success": True,
            "data": {
                "id": notification.id,
                "is_read": True,
            },
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def mark_all_notifications_read(request):
    """
    Mark all of the current user's unread notifications as read.

    Returns the number of notifications updated.
    """
    updated_count = SecurityNotification.objects.filter(
        user=request.user,
        is_read=False,
    ).update(is_read=True)

    return Response(
        {
            "success": True,
            "data": {
                "updated_count": updated_count,
            },
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def revoke_session(request, session_id):
    """
    Revoke a specific active session for the authenticated user.

    Reuses the existing secure revocation logic:
    - Scoped to request.user
    - Prevents revoking the current session
    - Deletes the corresponding Django session
    - Marks the UserSession as inactive
    """
    user_session = get_object_or_404(
        UserSession,
        id=session_id,
        user=request.user,
        is_active=True,
    )

    current_session_key = request.session.session_key

    if user_session.session_key == current_session_key:
        return Response(
            {
                "success": False,
                "error": {
                    "code": "cannot_revoke_current_session",
                    "message": "You cannot revoke your current session using this endpoint.",
                },
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    Session.objects.filter(session_key=user_session.session_key).delete()
    user_session.is_active = False
    user_session.save(update_fields=["is_active"])

    return Response(
        {
            "success": True,
            "data": {
                "id": user_session.id,
                "is_active": False,
            },
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def logout_other_sessions(request):
    """
    Log out all active sessions for the authenticated user except the current one.

    Reuses the existing secure logic:
    - Scoped to request.user
    - Keeps the current session active
    - Deletes corresponding Django sessions
    - Marks revoked UserSession records inactive
    - Creates a security notification
    """
    current_session_key = request.session.session_key

    other_sessions = UserSession.objects.filter(
        user=request.user,
        is_active=True,
    ).exclude(
        session_key=current_session_key,
    )

    other_session_keys = list(other_sessions.values_list("session_key", flat=True))

    Session.objects.filter(session_key__in=other_session_keys).delete()
    other_sessions.update(is_active=False)

    create_security_notification(
        user=request.user,
        notification_type=SecurityNotification.NOTIFICATION_TYPE_OTHER_SESSIONS_LOGGED_OUT,
        title="Other sessions logged out",
        message="All other active sessions have been logged out for your security.",
        request=request,
        session_key=current_session_key,
    )

    return Response(
        {
            "success": True,
            "data": {
                "revoked_sessions": len(other_session_keys),
                "message": "All other sessions have been logged out.",
            },
        },
        status=status.HTTP_200_OK,
    )


@swagger_auto_schema(
    method="post",
    operation_summary="Obtain JWT tokens",
    operation_description="Authenticate with email and password to receive JWT access and refresh tokens.",
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            "email": openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_EMAIL, example="user@example.com"),
            "password": openapi.Schema(type=openapi.TYPE_STRING, format=openapi.FORMAT_PASSWORD, example="secure-password"),
        },
        required=["email", "password"],
    ),
    responses={
        200: openapi.Response(
            "Successful login",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "success": openapi.Schema(type=openapi.TYPE_BOOLEAN, example=True),
                    "data": openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            "access": openapi.Schema(type=openapi.TYPE_STRING, example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."),
                            "refresh": openapi.Schema(type=openapi.TYPE_STRING, example="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."),
                            "user": openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    "id": openapi.Schema(type=openapi.TYPE_INTEGER, example=1),
                                    "email": openapi.Schema(type=openapi.TYPE_STRING, example="user@example.com"),
                                    "first_name": openapi.Schema(type=openapi.TYPE_STRING, example="John"),
                                    "last_name": openapi.Schema(type=openapi.TYPE_STRING, example="Doe"),
                                    "is_verified": openapi.Schema(type=openapi.TYPE_BOOLEAN, example=True),
                                },
                            ),
                        },
                    ),
                },
            ),
        ),
        400: openapi.Response(
            "Invalid credentials",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    "success": openapi.Schema(type=openapi.TYPE_BOOLEAN, example=False),
                    "error": openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            "code": openapi.Schema(type=openapi.TYPE_STRING, example="invalid_credentials"),
                            "message": openapi.Schema(type=openapi.TYPE_STRING, example="No active account found with the given credentials."),
                        },
                    ),
                },
            ),
        ),
    },
)
@api_view(["POST"])
@permission_classes([AllowAny])
def jwt_token_obtain_pair(request):
    """
    Obtain JWT access and refresh tokens using email and password.

    Integrates with existing brute-force protection and security logging.
    Never exposes whether an email exists on authentication failure.
    """
    email = request.data.get("email", "").strip().lower()
    password = request.data.get("password", "")
    ip_address = get_client_ip(request)
    user_agent_string = request.META.get("HTTP_USER_AGENT", "")
    parsed_ua = parse_user_agent(user_agent_string)

    is_blocked, _ = is_login_blocked(email, ip_address)
    if is_blocked:
        record_failed_attempt(email, ip_address)
        _record_failed_login_history_api(
            request=request,
            email=email,
            ip_address=ip_address,
            user_agent_string=user_agent_string,
            parsed_ua=parsed_ua,
        )
        return Response(
            {
                "success": False,
                "error": {
                    "code": "invalid_credentials",
                    "message": "No active account found with the given credentials.",
                },
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    serializer = CustomTokenObtainPairSerializer(data=request.data, context={"request": request})
    if not serializer.is_valid():
        user_obj = None
        try:
            user_obj = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            pass

        record_failed_attempt(email, ip_address)
        _record_failed_login_history_api(
            request=request,
            email=email,
            ip_address=ip_address,
            user_agent_string=user_agent_string,
            parsed_ua=parsed_ua,
            user=user_obj,
        )

        is_now_blocked, _ = is_login_blocked(email, ip_address)
        if is_now_blocked:
            notify_account_locked(email)

        return Response(
            {
                "success": False,
                "error": {
                    "code": "invalid_credentials",
                    "message": "No active account found with the given credentials.",
                },
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    user = serializer.user
    reset_failed_attempts(user.email, ip_address)
    _record_login_history_api(
        request=request,
        user=user,
        email=email,
        ip_address=ip_address,
        user_agent_string=user_agent_string,
        parsed_ua=parsed_ua,
    )

    refresh = RefreshToken.for_user(user)
    access = refresh.access_token

    response_data = {
        "success": True,
        "data": {
            "access": str(access),
            "refresh": str(refresh),
            "user": SafeUserSerializer(user).data,
        },
    }

    return Response(response_data, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([AllowAny])
def jwt_token_refresh(request):
    """
    Refresh an access token using a valid refresh token.

    Uses Simple JWT's built-in refresh logic.
    """
    from rest_framework_simplejwt.serializers import TokenRefreshSerializer
    from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

    try:
        serializer = TokenRefreshSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
    except (TokenError, InvalidToken):
        return Response(
            {
                "success": False,
                "error": {
                    "code": "invalid_token",
                    "message": "Token is invalid.",
                },
            },
            status=status.HTTP_401_UNAUTHORIZED,
        )

    return Response(
        {
            "success": True,
            "data": {
                "access": serializer.validated_data["access"],
            },
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([AllowAny])
def jwt_token_verify(request):
    """
    Verify an access token.

    Uses Simple JWT's built-in verify logic.
    """
    from rest_framework_simplejwt.serializers import TokenVerifySerializer
    from rest_framework_simplejwt.exceptions import TokenError, InvalidToken

    try:
        serializer = TokenVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
    except (TokenError, InvalidToken):
        return Response(
            {
                "success": False,
                "error": {
                    "code": "invalid_token",
                    "message": "Token is invalid.",
                },
            },
            status=status.HTTP_401_UNAUTHORIZED,
        )

    return Response(
        {
            "success": True,
            "data": {},
        },
        status=status.HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def jwt_logout(request):
    """
    Log out the authenticated user by blacklisting their refresh token.

    Requires authentication so that only the legitimate token holder
    can blacklist it. Does not destroy the Django browser session.
    """
    refresh_token = request.data.get("refresh")
    if not refresh_token:
        return Response(
            {
                "success": False,
                "error": {
                    "code": "missing_refresh_token",
                    "message": "A refresh token is required.",
                },
            },
            status=status.HTTP_400_BAD_REQUEST,
        )

    try:
        from rest_framework_simplejwt.tokens import RefreshToken
        token = RefreshToken(refresh_token)
        token.blacklist()
    except Exception:
        pass

    return Response(
        {
            "success": True,
            "data": {
                "message": "Successfully logged out.",
            },
        },
        status=status.HTTP_200_OK,
    )


def swagger_docs(request):
    """
    Swagger-style interactive API documentation.
    """
    return schema_view.with_ui("swagger", cache_timeout=0)(request)


def redoc_docs(request):
    """
    ReDoc-style API documentation.
    """
    return schema_view.with_ui("redoc", cache_timeout=0)(request)


def openapi_schema(request):
    """
    OpenAPI schema in JSON format.
    """
    return schema_view.without_ui(cache_timeout=0)(request)
