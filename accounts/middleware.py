import time

from django.conf import settings
from django.contrib.auth import logout
from django.shortcuts import redirect
from django.urls import reverse


class IdleSessionTimeoutMiddleware:
    """
    Enforce an idle session timeout for authenticated users.

    On each meaningful request from an authenticated user, this middleware
    updates a ``last_activity`` timestamp in the session. If the elapsed
    time since the last activity exceeds ``IDLE_SESSION_TIMEOUT`` seconds,
    the user is logged out and redirected to the login page with a
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
        ]

    def __call__(self, request):
        if request.user.is_authenticated:
            path = request.path
            is_exempt = any(path.startswith(prefix) for prefix in self.exempt_prefixes)

            if not is_exempt:
                now = time.time()
                last_activity = request.session.get("last_activity")

                if last_activity is not None and (now - last_activity) > self.timeout:
                    logout(request)
                    return redirect(
                        f"{reverse('accounts:login')}?session_expired=1"
                    )

                request.session["last_activity"] = now

        return self.get_response(request)
