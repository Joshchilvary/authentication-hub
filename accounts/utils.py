"""
Utility helpers for the accounts app.

Provides reusable functions for extracting client metadata
such as IP addresses and parsed user-agent information.
"""

import logging

from django.conf import settings
from django.contrib.auth import get_user_model

from datetime import timedelta

from django.db import transaction
from django.db.models import F
from django.utils import timezone

from .models import LoginHistory, LoginAttempt, SecurityNotification, SecurityRiskAssessment

logger = logging.getLogger(__name__)


def get_client_ip(request):
    """
    Extract the client IP address from the request.

    Checks ``HTTP_X_FORWARDED_FOR`` first when the immediate peer is in
    ``TRUSTED_PROXY_IPS``, then falls back to ``REMOTE_ADDR``. This
    prevents IP spoofing when the application is not behind a trusted
    reverse proxy.

    Trusted-proxy considerations
    ----------------------------
    Configure ``TRUSTED_PROXY_IPS`` in settings with the IP addresses of
    your reverse proxies. When the request comes from a trusted proxy,
    ``X-Forwarded-For`` is used. Otherwise, ``REMOTE_ADDR`` is used to
    prevent clients from spoofing their IP address.

    If your deployment sits behind a reverse proxy (for example
    nginx, Cloudflare, or a load balancer), configure the proxy
    to overwrite ``X-Forwarded-For`` with the actual client IP
    and restrict direct access to the Django application. You
    may also set ``SECURE_PROXY_SSL_HEADER`` in Django settings
    so the framework knows the proxy is trusted.

    Returns:
        str or None: The extracted IP address, or None if unavailable.
    """
    trusted_proxies = getattr(settings, 'TRUSTED_PROXY_IPS', [])
    remote_addr = request.META.get("REMOTE_ADDR")

    if trusted_proxies and remote_addr in trusted_proxies:
        x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
        if x_forwarded_for:
            return x_forwarded_for.split(",")[0].strip()

    return remote_addr


def parse_user_agent(user_agent_string):
    """
    Parse a user-agent string into browser, OS, and device info.

    Uses the ``user-agents`` library for robust parsing. If the
    library returns empty browser or OS values, a lightweight
    regex fallback handles the most common cases so that metadata
    is not left blank. If parsing fails entirely, empty strings are
    returned so that login history recording never breaks the
    authentication flow.
    """
    if not user_agent_string:
        return {
            "browser": "",
            "operating_system": "",
            "device_info": "",
        }

    try:
        from user_agents import parse

        ua = parse(user_agent_string)

        browser = ua.browser.family or ""
        operating_system = ua.os.family or ""

        if ua.is_mobile:
            device_info = "Mobile"
        elif ua.is_tablet:
            device_info = "Tablet"
        elif ua.is_pc:
            device_info = "PC"
        elif ua.is_bot:
            device_info = "Bot"
        else:
            device_info = ""

        if not browser or not operating_system:
            ua_lower = user_agent_string.lower()

            if not browser:
                if "edg/" in ua_lower:
                    browser = "Edge"
                elif "chrome/" in ua_lower:
                    browser = "Chrome"
                elif "safari/" in ua_lower and "chrome/" not in ua_lower:
                    browser = "Safari"
                elif "firefox/" in ua_lower:
                    browser = "Firefox"

            if not operating_system:
                if "windows" in ua_lower:
                    operating_system = "Windows"
                elif "mac os" in ua_lower or "macintosh" in ua_lower:
                    operating_system = "macOS"
                elif "android" in ua_lower:
                    operating_system = "Android"
                elif "iphone" in ua_lower or "ipad" in ua_lower:
                    operating_system = "iOS"
                elif "linux" in ua_lower:
                    operating_system = "Linux"

        return {
            "browser": browser,
            "operating_system": operating_system,
            "device_info": device_info,
        }
    except Exception:
        logger.debug("User-agent parsing failed", exc_info=True)
        return {
            "browser": "",
            "operating_system": "",
            "device_info": "",
        }


def is_login_blocked(email, ip_address):
    """
    Check whether a login attempt from the given email/IP is currently blocked.

    Returns a tuple of (is_blocked: bool, blocked_until: datetime or None).
    """
    now = timezone.now()

    email_attempt = LoginAttempt.objects.filter(
        email=email,
        ip_address__isnull=True,
    ).first()

    if email_attempt and email_attempt.blocked_until and email_attempt.blocked_until > now:
        return True, email_attempt.blocked_until

    ip_attempt = LoginAttempt.objects.filter(
        email='',
        ip_address=ip_address,
    ).first()

    if ip_attempt and ip_attempt.blocked_until and ip_attempt.blocked_until > now:
        return True, ip_attempt.blocked_until

    return False, None


def record_failed_attempt(email, ip_address):
    """
    Record a failed login attempt and apply throttling if thresholds are reached.

    Uses a 15-minute rolling window for both email-based and IP-based tracking.
    Account threshold: 5 failures → blocked for 15 minutes.
    IP threshold: 20 failures → blocked for 15 minutes.
    """
    now = timezone.now()
    window_start = now - timedelta(minutes=15)

    with transaction.atomic():
        email_attempt, created = LoginAttempt.objects.select_for_update().get_or_create(
            email=email,
            ip_address__isnull=True,
            defaults={
                'failed_attempts': 1,
                'first_attempt_at': now,
                'last_attempt_at': now,
            },
        )

        if not created:
            if email_attempt.last_attempt_at < window_start:
                email_attempt.failed_attempts = 1
                email_attempt.first_attempt_at = now
            else:
                email_attempt.failed_attempts = F('failed_attempts') + 1
            email_attempt.last_attempt_at = now
            email_attempt.save(update_fields=['failed_attempts', 'first_attempt_at', 'last_attempt_at'])
            email_attempt.refresh_from_db(fields=['failed_attempts', 'blocked_until'])

        if email_attempt.failed_attempts >= 5:
            email_attempt.blocked_until = now + timedelta(minutes=15)
            email_attempt.save(update_fields=['blocked_until'])

        ip_attempt, created = LoginAttempt.objects.select_for_update().get_or_create(
            email='',
            ip_address=ip_address,
            defaults={
                'failed_attempts': 1,
                'first_attempt_at': now,
                'last_attempt_at': now,
            },
        )

        if not created:
            if ip_attempt.last_attempt_at < window_start:
                ip_attempt.failed_attempts = 1
                ip_attempt.first_attempt_at = now
            else:
                ip_attempt.failed_attempts = F('failed_attempts') + 1
            ip_attempt.last_attempt_at = now
            ip_attempt.save(update_fields=['failed_attempts', 'first_attempt_at', 'last_attempt_at'])
            ip_attempt.refresh_from_db(fields=['failed_attempts', 'blocked_until'])

        if ip_attempt.failed_attempts >= 20:
            ip_attempt.blocked_until = now + timedelta(minutes=15)
            ip_attempt.save(update_fields=['blocked_until'])


def reset_failed_attempts(email, ip_address):
    """
    Reset failed-attempt counters after a successful login.

    Removes both the email-based and IP-based LoginAttempt records
    so that a successful authentication clears the throttle state
    for that account and source IP.
    """
    LoginAttempt.objects.filter(email=email, ip_address__isnull=True).delete()
    LoginAttempt.objects.filter(email='', ip_address=ip_address).delete()


def create_security_notification(
    user,
    notification_type,
    title,
    message,
    request=None,
    session_key=None,
):
    """
    Create a security notification for the given user.

    Uses request metadata when available to populate IP address,
    browser, operating system, and device info. Fails gracefully
    so that authentication flows are not interrupted by notification
    failures.
    """
    try:
        ip_address = None
        browser = ""
        operating_system = ""
        device_info = ""

        if request:
            ip_address = get_client_ip(request)
            user_agent_string = request.META.get("HTTP_USER_AGENT", "")
            parsed_ua = parse_user_agent(user_agent_string)
            browser = parsed_ua["browser"]
            operating_system = parsed_ua["operating_system"]
            device_info = parsed_ua["device_info"]

        SecurityNotification.objects.create(
            user=user,
            notification_type=notification_type,
            title=title,
            message=message,
            ip_address=ip_address,
            browser=browser,
            operating_system=operating_system,
            device_info=device_info,
            session_key=session_key or "",
        )
    except Exception:
        logger.exception("Failed to create security notification")


def notify_account_locked(email):
    """
    Create an ACCOUNT_LOCKED notification for the given email if the
    account exists and has not already been notified recently.
    """
    try:
        user = get_user_model().objects.filter(email__iexact=email).first()
        if not user:
            return

        recent_cutoff = timezone.now() - timedelta(minutes=15)
        already_notified = SecurityNotification.objects.filter(
            user=user,
            notification_type=SecurityNotification.NOTIFICATION_TYPE_ACCOUNT_LOCKED,
            created_at__gte=recent_cutoff,
        ).exists()
        if already_notified:
            return

        create_security_notification(
            user=user,
            notification_type=SecurityNotification.NOTIFICATION_TYPE_ACCOUNT_LOCKED,
            title="Account temporarily locked",
            message=(
                "Your account has been temporarily locked due to multiple "
                "failed login attempts. Please try again later."
            ),
        )
    except Exception:
        logger.exception("Failed to create account locked notification")


def calculate_login_risk_score(user, ip_address, user_agent_string, current_login_history_id=None):
    """
    Calculate a security risk score (0-100) for a successful login.

    Evaluates new device, new IP, new browser, new OS, and recent
    failed attempts. Returns a tuple of (score, level, reasons).
    """
    try:
        score = 0
        reasons = []

        parsed_ua = parse_user_agent(user_agent_string)
        browser = parsed_ua.get("browser", "")
        operating_system = parsed_ua.get("operating_system", "")
        device_info = parsed_ua.get("device_info", "")

        if not user or not user.pk:
            return 0, SecurityRiskAssessment.RISK_LEVEL_LOW, []

        history_qs = LoginHistory.objects.filter(user=user)
        if current_login_history_id:
            history_qs = history_qs.exclude(pk=current_login_history_id)

        # A: New device (browser + OS + device combo)
        if browser and operating_system and device_info:
            known_device = history_qs.filter(
                user=user,
                browser=browser,
                operating_system=operating_system,
                device_info=device_info,
            ).exists()
            if not known_device:
                score += 30
                reasons.append("New device detected")

        # B: New IP address
        if ip_address:
            known_ip = history_qs.filter(ip_address=ip_address).exists()
            if not known_ip:
                score += 25
                reasons.append("New IP address detected")

        # C: Recent failed login attempts
        recent_cutoff = timezone.now() - timedelta(minutes=15)
        recent_failures = LoginHistory.objects.filter(
            user=user,
            event_type=LoginHistory.EVENT_TYPE_LOGIN_FAILED,
            timestamp__gte=recent_cutoff,
        ).count()
        if recent_failures > 0:
            failure_score = min(recent_failures * 10, 30)
            score += failure_score
            reasons.append(f"Recent failed login attempts detected ({recent_failures})")

        # D: New browser
        if browser:
            known_browser = history_qs.filter(browser=browser).exists()
            if not known_browser:
                score += 15
                reasons.append("New browser detected")

        # E: New operating system
        if operating_system:
            known_os = history_qs.filter(operating_system=operating_system).exists()
            if not known_os:
                score += 15
                reasons.append("New operating system detected")

        # F: Multiple risk factors bonus
        if len(reasons) >= 3:
            score += 10
            reasons.append("Multiple risk factors detected")

        score = min(score, 100)

        if score <= 29:
            level = SecurityRiskAssessment.RISK_LEVEL_LOW
        elif score <= 59:
            level = SecurityRiskAssessment.RISK_LEVEL_MEDIUM
        elif score <= 79:
            level = SecurityRiskAssessment.RISK_LEVEL_HIGH
        else:
            level = SecurityRiskAssessment.RISK_LEVEL_CRITICAL

        return score, level, reasons
    except Exception:
        logger.exception("Failed to calculate login risk score")
        return 0, SecurityRiskAssessment.RISK_LEVEL_LOW, []


def create_security_risk_assessment(user, login_history, ip_address, browser, operating_system, device_info, session_key=None):
    """
    Create a SecurityRiskAssessment for a successful login.

    Calculates the risk score, creates the assessment record, and
    generates a security notification when the risk level is HIGH
    or CRITICAL.
    """
    try:
        user_agent_string = ""
        if browser or operating_system or device_info:
            user_agent_string = login_history.user_agent if login_history else ""

        score, level, reasons = calculate_login_risk_score(
            user=user,
            ip_address=ip_address,
            user_agent_string=user_agent_string,
            current_login_history_id=login_history.pk if login_history else None,
        )

        assessment = SecurityRiskAssessment.objects.create(
            user=user,
            login_history=login_history,
            ip_address=ip_address,
            browser=browser,
            operating_system=operating_system,
            device_info=device_info,
            risk_score=score,
            risk_level=level,
            risk_reasons="; ".join(reasons),
            session_key=session_key or "",
        )

        if level in (SecurityRiskAssessment.RISK_LEVEL_HIGH, SecurityRiskAssessment.RISK_LEVEL_CRITICAL):
            create_security_notification(
                user=user,
                notification_type=SecurityNotification.NOTIFICATION_TYPE_NEW_LOGIN,
                title=f"Suspicious login detected ({level})",
                message=(
                    f"A login was detected with risk level {level.upper()} "
                    f"(score: {score}). "
                    + "; ".join(reasons)
                    + ". If this was not you, review your active sessions and change your password."
                ),
                session_key=session_key,
            )

        return assessment
    except Exception:
        logger.exception("Failed to create security risk assessment")
        return None
