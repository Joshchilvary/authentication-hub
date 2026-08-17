import time

from datetime import timedelta
from django.conf import settings
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone

from .models import LoginHistory, SecurityNotification, UserSession
from .utils import get_client_ip, parse_user_agent, create_security_notification


class IdleSessionTimeoutMiddleware:
    """
    Enforce an idle session timeout for authenticated users.

    On each meaningful request from an authenticated user, this middleware
    updates a ``last_activity`` timestamp in the session. If the elapsed
    time since the last activity exceeds ``IDLE_SESSION_TIMEOUT`` seconds,
    the user is logged out, a ``Session Expired`` event is recorded in
    ``LoginHistory``, and the user is redirected to the login page with a
    ``session_expired`` query parameter.

    Static and media requests are exempt because they do not represent
    meaningful user interaction.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.timeout = getattr(settings, "IDLE_SESSION_TIMEOUT", 300)
        self.exempt_prefixes = [
            settings.STATIC_URL,
            settings.MEDIA_URL,
            '/admin/',
        ]

    def __call__(self, request):
        if request.user.is_authenticated:
            path = request.path
            is_exempt = any(path.startswith(prefix) for prefix in self.exempt_prefixes)

            if not is_exempt:
                now = time.time()
                last_activity = request.session.get("last_activity")

                if last_activity is not None and (now - last_activity) > self.timeout:
                    self._record_session_expired(request)
                    self._mark_session_inactive(request)
                    logout(request)
                    return redirect(
                        f"{reverse('accounts:login')}?session_expired=1"
                    )

                request.session["last_activity"] = now
                self._update_user_session_activity(request)

        return self.get_response(request)

    def _update_user_session_activity(self, request):
        """
        Update the last_activity timestamp on the active UserSession.

        Keeps the UserSession record in sync with the idle-timeout
        session data for authenticated frontend users. Skips admin
        and static/media requests because they are exempt above.
        """
        try:
            session_key = request.session.session_key
            if not session_key:
                return

            UserSession.objects.filter(
                session_key=session_key,
                user=request.user,
                is_active=True,
            ).update(last_activity=timezone.now())
        except Exception:
            import logging

            logger = logging.getLogger(__name__)
            logger.exception("Failed to update user session activity")

    def _mark_session_inactive(self, request):
        """
        Mark the current UserSession as inactive before logout.

        Ensures that when the idle timeout expires, the corresponding
        UserSession record is preserved but flagged inactive.
        """
        try:
            session_key = request.session.session_key
            if not session_key:
                return

            UserSession.objects.filter(
                session_key=session_key,
                user=request.user,
                is_active=True,
            ).update(is_active=False)
        except Exception:
            import logging

            logger = logging.getLogger(__name__)
            logger.exception("Failed to mark user session inactive")

    def _record_session_expired(self, request):
        """
        Record a session expiration event in LoginHistory.

        Creates an audit record before the session is flushed by
        ``logout(request)`` so the session key and authenticated user
        are still available. Duplicate records for the same session
        are prevented by checking for an existing recent event.
        """
        try:
            user = request.user
            if not user.is_authenticated:
                return

            session_key = request.session.session_key
            if session_key:
                recent_cutoff = timezone.now() - timedelta(seconds=5)
                already_recorded = LoginHistory.objects.filter(
                    event_type=LoginHistory.EVENT_TYPE_SESSION_EXPIRED,
                    session_key=session_key,
                    timestamp__gte=recent_cutoff,
                ).exists()
                if already_recorded:
                    return

            ip_address = get_client_ip(request)
            user_agent_string = request.META.get("HTTP_USER_AGENT", "")
            parsed_ua = parse_user_agent(user_agent_string)

            LoginHistory.objects.create(
                user=user,
                email_attempted=user.email,
                ip_address=ip_address,
                user_agent=user_agent_string,
                browser=parsed_ua["browser"],
                operating_system=parsed_ua["operating_system"],
                device_info=parsed_ua["device_info"],
                event_type=LoginHistory.EVENT_TYPE_SESSION_EXPIRED,
                session_key=session_key,
            )

            create_security_notification(
                user=user,
                notification_type=SecurityNotification.NOTIFICATION_TYPE_SESSION_EXPIRED,
                title="Session expired",
                message="Your session has expired due to inactivity.",
                session_key=session_key,
            )
        except Exception:
            import logging

            logger = logging.getLogger(__name__)
            logger.exception("Failed to record session expired history")
