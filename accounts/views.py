"""
Views for the accounts app.

Handles user registration, authentication, dashboard, logout,
and email verification using Django's token generation utilities.
"""

from django.contrib import messages
from django.contrib.auth import login, logout, update_session_auth_hash, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.views import PasswordChangeView, PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
from django.conf import settings
from datetime import timedelta
from django.core.paginator import Paginator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode, url_has_allowed_host_and_scheme
from django.db import transaction
from django.utils import timezone

from django.contrib.sessions.models import Session
from django.shortcuts import get_object_or_404

from .forms import LoginForm, ProfileUpdateForm, RegistrationForm
from .models import LoginHistory, SecurityNotification, SecurityRiskAssessment, UserSession
from .tokens import email_verification_token
from .utils import get_client_ip, parse_user_agent, is_login_blocked, record_failed_attempt, reset_failed_attempts, create_security_notification, notify_account_locked, calculate_login_risk_score, create_security_risk_assessment


class CustomPasswordResetView(PasswordResetView):
    """
    Custom password reset view.

    Uses Django's built-in PasswordResetView with custom templates
    for the form and email. Ensures the user is not logged in during
    the reset process and does not reveal whether an email exists.
    Records a password reset request event in LoginHistory.
    """

    template_name = "accounts/password_reset.html"
    email_template_name = "accounts/emails/password_reset_email.html"
    subject_template_name = "accounts/emails/password_reset_subject.txt"
    success_url = reverse_lazy("accounts:password_reset_done")

    def form_valid(self, form):
        """
        Record the password reset request before delegating to the parent.
        """
        email = form.cleaned_data.get("email", "")
        if email:
            ip_address = get_client_ip(self.request)
            user_agent_string = self.request.META.get("HTTP_USER_AGENT", "")
            parsed_ua = parse_user_agent(user_agent_string)

            user = None
            try:
                user = get_user_model().objects.get(email__iexact=email)
            except get_user_model().DoesNotExist:
                user = None

            if user:
                create_security_notification(
                    user=user,
                    notification_type=SecurityNotification.NOTIFICATION_TYPE_PASSWORD_RESET,
                    title="Password reset requested",
                    message="A password reset was requested for your account.",
                    request=self.request,
                )

            try:
                LoginHistory.objects.create(
                    user=user,
                    email_attempted=email,
                    ip_address=ip_address,
                    user_agent=user_agent_string,
                    browser=parsed_ua["browser"],
                    operating_system=parsed_ua["operating_system"],
                    device_info=parsed_ua["device_info"],
                    event_type=LoginHistory.EVENT_TYPE_PASSWORD_RESET_REQUEST,
                )
            except Exception:
                import logging

                logger = logging.getLogger(__name__)
                logger.exception("Failed to record password reset request history")

        return super().form_valid(form)


class CustomPasswordResetDoneView(PasswordResetDoneView):
    """
    Password reset done view.

    Displays a generic message without revealing whether the supplied
    email address exists in the database.
    """

    template_name = "accounts/password_reset_done.html"


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    """
    Custom password reset confirmation view.

    Uses Django's built-in SetPasswordForm and token validation.
    Renders a custom confirmation template and redirects to the
    complete page on success. Shows a dedicated error page when
    the reset token is invalid, expired, or has already been used.
    Records a password reset completion event in LoginHistory.
    """

    template_name = "accounts/password_reset_confirm.html"
    success_url = reverse_lazy("accounts:password_reset_complete")

    def form_valid(self, form):
        """
        Record the password reset completion after the password is saved.
        Invalidate other active sessions for the user when the password
        is reset through the recovery flow.
        """
        response = super().form_valid(form)

        user = form.user
        if user and user.pk:
            try:
                ip_address = get_client_ip(self.request)
                user_agent_string = self.request.META.get("HTTP_USER_AGENT", "")
                parsed_ua = parse_user_agent(user_agent_string)

                current_session_key = self.request.session.session_key

                other_sessions = UserSession.objects.filter(
                    user=user,
                    is_active=True,
                )
                if current_session_key:
                    other_sessions = other_sessions.exclude(
                        session_key=current_session_key
                    )

                other_session_keys = list(
                    other_sessions.values_list("session_key", flat=True)
                )

                Session.objects.filter(session_key__in=other_session_keys).delete()
                other_sessions.update(is_active=False)

                LoginHistory.objects.create(
                    user=user,
                    email_attempted=user.email,
                    ip_address=ip_address,
                    user_agent=user_agent_string,
                    browser=parsed_ua["browser"],
                    operating_system=parsed_ua["operating_system"],
                    device_info=parsed_ua["device_info"],
                    event_type=LoginHistory.EVENT_TYPE_PASSWORD_RESET_COMPLETED,
                    session_key=current_session_key,
                )

                create_security_notification(
                    user=user,
                    notification_type=SecurityNotification.NOTIFICATION_TYPE_PASSWORD_RESET,
                    title="Password reset completed",
                    message=(
                        "Your account password was reset successfully. "
                        "All other active sessions have been logged out for your security."
                    ),
                    request=self.request,
                    session_key=current_session_key,
                )
            except Exception:
                import logging

                logger = logging.getLogger(__name__)
                logger.exception("Failed to record password reset completion history")

        return response


class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    """
    Password reset complete view.

    Displays a success message and a link to the login page.
    """

    template_name = "accounts/password_reset_complete.html"


def register(request):
    """
    Handle user registration.

    On GET: Display an empty registration form.
    On POST: Validate the submitted form, create a new user if valid,
             send an email verification link, and redirect to the login
             page with a success message. The user is NOT logged in
             automatically.

    Returns:
        HttpResponse: Rendered registration template or redirect to login.
    """
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            user.is_verified = False
            user.save()

            current_site = get_current_site(request)
            subject = "Verify your email address"
            message = render_to_string("accounts/emails/verify_email.html", {
                "user": user,
                "domain": current_site.domain,
                "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                "token": email_verification_token.make_token(user),
            })

            send_mail(
                subject=subject,
                message=message,
                from_email=None,
                recipient_list=[user.email],
                html_message=message,
            )

            messages.success(request, "Your account has been created successfully. Please check your email to verify your account.")
            return redirect("accounts:login")
    else:
        form = RegistrationForm()

    return render(request, "accounts/register.html", {"form": form})


def _record_login_history(request, user, form):
    """
    Record a successful login event in LoginHistory.

    Extracts client metadata from the request and creates an audit
    record. Database or parsing errors are caught and logged so that
    metadata failures do not break the authentication flow.
    """
    try:
        email_attempted = form.cleaned_data.get("username", user.email)
        if isinstance(email_attempted, str):
            email_attempted = email_attempted.strip().lower()

        ip_address = get_client_ip(request)
        user_agent_string = request.META.get("HTTP_USER_AGENT", "")
        parsed_ua = parse_user_agent(user_agent_string)

        new_device = False
        if user.is_authenticated or user.pk:
            matching_sessions = UserSession.objects.filter(
                user=user,
                browser=parsed_ua["browser"],
                operating_system=parsed_ua["operating_system"],
                device_info=parsed_ua["device_info"],
            )
            if not matching_sessions.exists():
                new_device = True

        LoginHistory.objects.create(
            user=user,
            email_attempted=email_attempted,
            ip_address=ip_address,
            user_agent=user_agent_string,
            browser=parsed_ua["browser"],
            operating_system=parsed_ua["operating_system"],
            device_info=parsed_ua["device_info"],
            new_device=new_device,
            event_type=LoginHistory.EVENT_TYPE_LOGIN_SUCCESS,
            session_key=request.session.session_key,
        )
        login_history = LoginHistory.objects.filter(user=user).order_by('-timestamp').first()

        notification_type = SecurityNotification.NOTIFICATION_TYPE_NEW_DEVICE_LOGIN if new_device else SecurityNotification.NOTIFICATION_TYPE_NEW_LOGIN
        create_security_notification(
            user=user,
            notification_type=notification_type,
            title="New login detected" if not new_device else "New device login detected",
            message=(
                f"A new login was detected on your account from "
                f"{parsed_ua['browser']} on {parsed_ua['operating_system']} "
                f"({parsed_ua['device_info']})."
            ),
            request=request,
            session_key=request.session.session_key,
        )

        if new_device:
            messages.info(
                request,
                "A new device or browser was used to log in to your account.",
            )

            try:
                current_site = get_current_site(request)
                context = {
                    "user": user,
                    "domain": current_site.domain,
                    "timestamp": timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "browser": parsed_ua["browser"],
                    "operating_system": parsed_ua["operating_system"],
                    "device_info": parsed_ua["device_info"],
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
    except Exception:
        import logging

        logger = logging.getLogger(__name__)
        logger.exception("Failed to record login history")


def _record_failed_login_history(request, form):
    """
    Record a failed login event in LoginHistory.

    Extracts client metadata from the request and creates an audit
    record for an unsuccessful authentication attempt. Database or
    parsing errors are caught and logged so that metadata failures
    do not break the authentication flow.
    """
    try:
        email_attempted = form.cleaned_data.get("username")
        if not email_attempted:
            email_attempted = request.POST.get("username", "")
        if isinstance(email_attempted, str):
            email_attempted = email_attempted.strip().lower()

        user = None
        if email_attempted:
            try:
                user = get_user_model().objects.get(email__iexact=email_attempted)
            except get_user_model().DoesNotExist:
                user = None

        ip_address = get_client_ip(request)
        user_agent_string = request.META.get("HTTP_USER_AGENT", "")
        parsed_ua = parse_user_agent(user_agent_string)

        LoginHistory.objects.create(
            user=user,
            email_attempted=email_attempted,
            ip_address=ip_address,
            user_agent=user_agent_string,
            browser=parsed_ua["browser"],
            operating_system=parsed_ua["operating_system"],
            device_info=parsed_ua["device_info"],
            event_type=LoginHistory.EVENT_TYPE_LOGIN_FAILED,
        )
    except Exception:
        import logging

        logger = logging.getLogger(__name__)
        logger.exception("Failed to record failed login history")


def _record_throttled_login_history(request, email, ip_address):
    """
    Record a throttled/blocked login attempt in LoginHistory.

    Creates an audit record for a request that was rejected by the
    brute-force protection system. Uses a generic event type so that
    the record does not reveal whether the email exists.
    """
    try:
        user = None
        if email:
            try:
                user = get_user_model().objects.get(email__iexact=email)
            except get_user_model().DoesNotExist:
                user = None

        user_agent_string = request.META.get("HTTP_USER_AGENT", "")
        parsed_ua = parse_user_agent(user_agent_string)

        LoginHistory.objects.create(
            user=user,
            email_attempted=email,
            ip_address=ip_address,
            user_agent=user_agent_string,
            browser=parsed_ua["browser"],
            operating_system=parsed_ua["operating_system"],
            device_info=parsed_ua["device_info"],
            event_type=LoginHistory.EVENT_TYPE_LOGIN_BLOCKED,
        )
    except Exception:
        import logging

        logger = logging.getLogger(__name__)
        logger.exception("Failed to record throttled login history")


def _record_password_change_history(request, user):
    """
    Record a password change event in LoginHistory.
    """
    try:
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
            event_type=LoginHistory.EVENT_TYPE_PASSWORD_CHANGE,
            session_key=request.session.session_key,
        )
    except Exception:
        import logging

        logger = logging.getLogger(__name__)
        logger.exception("Failed to record password change history")


def _record_logout_history(request):
    """
    Record a logout event in LoginHistory.

    Creates an audit record for a user-initiated logout. The record
    is created before calling ``logout(request)`` so the session key
    and authenticated user are still available.
    """
    try:
        user = request.user
        if not user.is_authenticated:
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
            event_type=LoginHistory.EVENT_TYPE_LOGOUT,
            session_key=request.session.session_key,
        )
    except Exception:
        import logging

        logger = logging.getLogger(__name__)
        logger.exception("Failed to record logout history")


def _record_user_session(request, user, remember_me):
    """
    Create or update a UserSession record for a successful login.

    Captures client metadata and calculates session expiry based
    on the Remember Me choice. If the session_key already exists,
    the existing record is updated rather than deleted, preserving
    the audit trail.
    """
    try:
        session_key = request.session.session_key
        if not session_key:
            return

        ip_address = get_client_ip(request)
        user_agent_string = request.META.get("HTTP_USER_AGENT", "")
        parsed_ua = parse_user_agent(user_agent_string)

        expires_at = None
        if remember_me:
            session_age = getattr(settings, "SESSION_COOKIE_AGE", 1209600)
            expires_at = timezone.now() + timedelta(seconds=session_age)

        UserSession.objects.update_or_create(
            session_key=session_key,
            defaults={
                "user": user,
                "ip_address": ip_address,
                "user_agent": user_agent_string,
                "browser": parsed_ua["browser"],
                "operating_system": parsed_ua["operating_system"],
                "device_info": parsed_ua["device_info"],
                "last_activity": timezone.now(),
                "expires_at": expires_at,
                "remember_me": remember_me,
                "is_active": True,
            },
        )
    except Exception:
        import logging

        logger = logging.getLogger(__name__)
        logger.exception("Failed to record user session")


def login_view(request):
    """
    Handle user login via email and password.

    On GET: Display an empty login form.
    On POST: Validate credentials using Django's authentication system,
             log the user in, and redirect to the dashboard or the
             page originally requested via the 'next' parameter.

    If the user is already authenticated, they are immediately redirected
    to the dashboard.

    Returns:
        HttpResponse: Rendered login template or redirect to dashboard.
    """
    if request.user.is_authenticated:
        return redirect("accounts:dashboard")

    redirect_url = request.GET.get("next")
    if redirect_url and not url_has_allowed_host_and_scheme(
        url=redirect_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        redirect_url = None

    if request.method == "POST":
        email = request.POST.get("username", "").strip().lower()
        ip_address = get_client_ip(request)

        is_blocked, blocked_until = is_login_blocked(email, ip_address)
        if is_blocked:
            remaining = blocked_until - timezone.now()
            total_seconds = int(remaining.total_seconds())
            minutes = total_seconds // 60
            seconds = total_seconds % 60

            if minutes > 0:
                msg = f"Too many login attempts. Please try again in {minutes} minute{'s' if minutes != 1 else ''}."
            else:
                msg = f"Too many login attempts. Please try again in {seconds} seconds."

            messages.error(request, msg)

            _record_throttled_login_history(request, email, ip_address)

            form = LoginForm(request, data=request.POST)
            return render(request, "accounts/login.html", {"form": form})

        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            remember_me = form.cleaned_data.get("remember_me")
            login(request, user)
            if not remember_me:
                request.session.set_expiry(0)
            messages.success(request, "You have been logged in successfully.")

            reset_failed_attempts(user.email, ip_address)

            _record_login_history(request, user, form)
            _record_user_session(request, user, remember_me)

            login_history = LoginHistory.objects.filter(user=user).order_by('-timestamp').first()
            if login_history:
                parsed_ua = parse_user_agent(request.META.get("HTTP_USER_AGENT", ""))
                create_security_risk_assessment(
                    user=user,
                    login_history=login_history,
                    ip_address=ip_address,
                    browser=parsed_ua.get("browser", ""),
                    operating_system=parsed_ua.get("operating_system", ""),
                    device_info=parsed_ua.get("device_info", ""),
                    session_key=request.session.session_key,
                )

            return redirect(redirect_url or "accounts:dashboard")
        else:
            _record_failed_login_history(request, form)
            record_failed_attempt(email, ip_address)

            is_now_blocked, _ = is_login_blocked(email, ip_address)
            if is_now_blocked:
                notify_account_locked(email)
    else:
        form = LoginForm()

    return render(request, "accounts/login.html", {"form": form})


@login_required
def dashboard(request):
    """
    Render the user dashboard.

    Only authenticated users can access this view. If a user is not
    authenticated, Django's @login_required decorator automatically
    redirects them to the login page.

    Args:
        request: The HTTP request object containing the authenticated user.

    Returns:
        HttpResponse: Rendered dashboard template with the user object.
    """
    return render(request, "accounts/dashboard.html", {"user": request.user})


@login_required
def logout_view(request):
    """
    Log out the current user and redirect to the login page.

    Only authenticated users can access this view. If the user is not
    authenticated, Django's @login_required decorator automatically
    redirects them to the login page.

    Before logging out, a logout event is recorded in LoginHistory
    so that the session key and authenticated user are still available.

    Args:
        request: The HTTP request object for the currently authenticated user.

    Returns:
        HttpResponseRedirect: Redirect to the login page with a success message.
    """
    _record_logout_history(request)

    try:
        session_key = request.session.session_key
        if session_key:
            UserSession.objects.filter(
                session_key=session_key,
                user=request.user,
                is_active=True,
            ).update(is_active=False)
    except Exception:
        import logging

        logger = logging.getLogger(__name__)
        logger.exception("Failed to mark user session inactive on logout")

    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect("accounts:login")


@login_required
def profile(request):
    """
    Display the authenticated user's profile dashboard.

    Only authenticated users can access this view. If a user is not
    authenticated, Django's @login_required decorator automatically
    redirects them to the login page.

    Uses request.user to avoid an unnecessary database query since the
    user is already available in the request object after authentication.

    The dashboard enriches the profile page with lightweight security
    summaries pulled from existing models. All queries are scoped to
    request.user to prevent IDOR exposure.

    Args:
        request: The HTTP request object containing the authenticated user.

    Returns:
        HttpResponse: Rendered profile template with user and summary context.
    """
    user = request.user

    active_sessions_count = UserSession.objects.filter(
        user=user,
        is_active=True,
    ).count()

    latest_login = (
        LoginHistory.objects.filter(
            user=user,
            event_type=LoginHistory.EVENT_TYPE_LOGIN_SUCCESS,
        )
        .order_by("-timestamp")
        .first()
    )

    latest_risk_assessment = (
        SecurityRiskAssessment.objects.filter(
            user=user,
        )
        .order_by("-created_at")
        .first()
    )

    context = {
        "user": user,
        "active_sessions_count": active_sessions_count,
        "latest_login": latest_login,
        "latest_risk_assessment": latest_risk_assessment,
        "latest_risk_assessment_risk_reasons": latest_risk_assessment.risk_reasons.split("; ") if latest_risk_assessment and latest_risk_assessment.risk_reasons else [],
        "is_verified": user.is_verified,
    }

    return render(request, "accounts/profile.html", context)


@login_required
def edit_profile(request):
    """
    Allow the authenticated user to update their profile information.

    Only authenticated users can access this view. If a user is not
    authenticated, Django's @login_required decorator automatically
    redirects them to the login page.

    On GET: Display a form pre-filled with the user's current profile data.
    On POST: Validate the submitted form with both request.POST and
             request.FILES (required for file uploads like profile pictures),
             save the updated profile if valid, display a success message,
             and redirect back to the profile page. If the form is invalid,
             redisplay the form with validation errors.

    instance=request.user is passed to the form so that the form loads
    the existing user data for editing and updates the same user instance
    rather than creating a new one.

    request.FILES is passed to the form to handle file uploads, specifically
    the profile_picture field which uses a ClearableFileInput widget.
    Without request.FILES, uploaded files would be silently ignored.

    Args:
        request: The HTTP request object containing the authenticated user
                 and optional uploaded files.

    Returns:
        HttpResponse: Rendered edit profile template with the form, or
                      a redirect to the profile page on success.
    """
    if request.method == "POST":
        form = ProfileUpdateForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Your profile has been updated successfully.")
            return redirect("accounts:profile")
        else:
            messages.error(request, "Please correct the errors below and try again.")
    else:
        form = ProfileUpdateForm(instance=request.user)

    return render(request, "accounts/edit_profile.html", {"form": form})


class CustomPasswordChangeView(LoginRequiredMixin, PasswordChangeView):
    """
    View for authenticated users to change their password.

    Uses Django's built-in PasswordChangeForm for validation.
    Calls update_session_auth_hash() to keep the user logged in
    after the password change.
    Displays a success message and redirects to the profile page.
    """

    template_name = "accounts/change_password.html"
    form_class = PasswordChangeForm
    success_url = reverse_lazy("accounts:profile")

    def form_valid(self, form):
        """
        Save the new password, update the session auth hash,
        invalidate all other active sessions for the user, display
        a success message, and redirect to the profile page.
        """
        user = form.save()
        current_session_key = self.request.session.session_key
        update_session_auth_hash(self.request, user)

        with transaction.atomic():
            other_sessions = UserSession.objects.filter(
                user=user,
                is_active=True,
            ).exclude(
                session_key=current_session_key,
            )

            other_session_keys = list(
                other_sessions.values_list("session_key", flat=True)
            )

            Session.objects.filter(session_key__in=other_session_keys).delete()

            other_sessions.update(is_active=False)

        messages.success(
            self.request,
            "Your password has been changed successfully. All other active sessions have been logged out for your security.",
        )

        try:
            current_site = get_current_site(self.request)
            context = {
                "user": user,
                "domain": current_site.domain,
                "timestamp": timezone.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            subject = "Your password was changed"
            plain_message = render_to_string("accounts/emails/password_changed_notification.txt", context)
            html_message = render_to_string("accounts/emails/password_changed_notification.html", context)

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
            logger.exception("Failed to send password changed notification email")

        _record_password_change_history(self.request, user)

        create_security_notification(
            user=user,
            notification_type=SecurityNotification.NOTIFICATION_TYPE_PASSWORD_CHANGED,
            title="Password changed",
            message="Your account password was changed successfully.",
            request=self.request,
            session_key=self.request.session.session_key,
        )

        return redirect("accounts:profile")


@login_required
def settings_view(request):
    """
    Render the account settings page.

    Only authenticated users can access this view. Groups
    account management options into cards for Profile, Security,
    Profile Picture, and Danger Zone.

    Args:
        request: The HTTP request object containing the authenticated user.

    Returns:
        HttpResponse: Rendered settings template with the user object.
    """
    return render(request, "accounts/settings.html", {"user": request.user})


@login_required
def security_dashboard(request):
    """
    Display a security overview for the authenticated user.

    Shows password status, active sessions count, most recent login
    activity, most recent new-login alert, email verification status,
    and quick links to existing security-related pages. All queries
    are scoped to request.user. No session keys, passwords, or tokens
    are exposed.
    """
    active_sessions_count = UserSession.objects.filter(
        user=request.user,
        is_active=True,
    ).count()

    latest_login = (
        LoginHistory.objects.filter(
            user=request.user,
            event_type=LoginHistory.EVENT_TYPE_LOGIN_SUCCESS,
        )
        .order_by("-timestamp")
        .first()
    )

    latest_new_device_login = (
        LoginHistory.objects.filter(
            user=request.user,
            event_type=LoginHistory.EVENT_TYPE_LOGIN_SUCCESS,
            new_device=True,
        )
        .order_by("-timestamp")
        .first()
    )

    latest_risk_assessment = (
        SecurityRiskAssessment.objects.filter(
            user=request.user,
        )
        .order_by("-created_at")
        .first()
    )

    context = {
        "user": request.user,
        "active_sessions_count": active_sessions_count,
        "latest_login": latest_login,
        "latest_new_device_login": latest_new_device_login,
        "latest_risk_assessment": latest_risk_assessment,
        "latest_risk_assessment_risk_reasons": latest_risk_assessment.risk_reasons.split("; ") if latest_risk_assessment and latest_risk_assessment.risk_reasons else [],
        "is_verified": request.user.is_verified,
    }

    return render(request, "accounts/security_dashboard.html", context)


@login_required
def active_sessions(request):
    """
    Display the authenticated user's active sessions.

    Retrieves only the current user's active UserSession records,
    ordered by most recent activity. Determines which session is
    the current session server-side and passes an ``is_current``
    boolean for each session. Does not expose session keys to the
    frontend.

    Args:
        request: The HTTP request object containing the authenticated user.

    Returns:
        HttpResponse: Rendered active sessions template with session data.
    """
    sessions = UserSession.objects.filter(
        user=request.user,
        is_active=True,
    ).order_by("-last_activity")

    current_session_key = request.session.session_key
    sessions_with_flags = []
    for session in sessions:
        sessions_with_flags.append({
            "id": session.id,
            "browser": session.browser,
            "operating_system": session.operating_system,
            "device_info": session.device_info,
            "ip_address": session.ip_address,
            "created_at": session.created_at,
            "last_activity": session.last_activity,
            "remember_me": session.remember_me,
            "is_current": session.session_key == current_session_key,
        })

    return render(
        request,
        "accounts/active_sessions.html",
        {"sessions": sessions_with_flags},
    )


@login_required
def revoke_session(request, session_id):
    """
    Revoke a specific active session for the authenticated user.

    Accepts only POST requests. Finds the UserSession by primary key
    scoped to the current user, ensures it is not the current session,
    deletes the corresponding Django session, and marks the UserSession
    as inactive. Redirects back to Active Sessions with a result message.
    """
    if request.method != "POST":
        return redirect("accounts:active_sessions")

    user_session = get_object_or_404(
        UserSession,
        id=session_id,
        user=request.user,
        is_active=True,
    )

    current_session_key = request.session.session_key

    if user_session.session_key == current_session_key:
        messages.error(
            request,
            "You cannot revoke your current session using this form.",
        )
        return redirect("accounts:active_sessions")

    Session.objects.filter(session_key=user_session.session_key).delete()

    user_session.is_active = False
    user_session.save(update_fields=["is_active"])

    messages.success(request, "The selected session has been logged out.")
    return redirect("accounts:active_sessions")


@login_required
def logout_other_sessions(request):
    """
    Log out all active sessions for the authenticated user except the current one.

    Accepts only POST requests. Finds all active UserSession records
    for the current user excluding the current session key, deletes
    the corresponding Django sessions, and marks the UserSession records
    as inactive. Redirects back to Active Sessions with a success message.
    """
    if request.method != "POST":
        return redirect("accounts:active_sessions")

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

    messages.success(request, "All other sessions have been logged out successfully.")
    return redirect("accounts:active_sessions")


@login_required
def emergency_security(request):
    """
    Emergency security action to immediately secure the user's account.

    On GET: Display a confirmation page explaining the consequences.
    On POST: Revoke ALL active sessions for the authenticated user
             (including the current session), record an audit event,
             create a security notification, log the user out, and
             redirect to the login page.

    All database operations are scoped to request.user to prevent
    IDOR attacks. No user-supplied identifiers are trusted.
    """
    if request.method == "POST":
        user = request.user
        current_session_key = request.session.session_key

        ip_address = get_client_ip(request)
        user_agent_string = request.META.get("HTTP_USER_AGENT", "")
        if not user_agent_string and current_session_key:
            try:
                current_session = UserSession.objects.filter(
                    session_key=current_session_key,
                    user=user,
                ).first()
                if current_session and current_session.user_agent:
                    user_agent_string = current_session.user_agent
            except Exception:
                pass
        parsed_ua = parse_user_agent(user_agent_string)

        LoginHistory.objects.create(
            user=user,
            email_attempted=user.email,
            ip_address=ip_address,
            user_agent=user_agent_string,
            browser=parsed_ua["browser"],
            operating_system=parsed_ua["operating_system"],
            device_info=parsed_ua["device_info"],
            event_type=LoginHistory.EVENT_TYPE_EMERGENCY_SECURITY_ACTION,
            session_key=current_session_key,
        )

        all_active_sessions = UserSession.objects.filter(
            user=user,
            is_active=True,
        )
        all_session_keys = list(
            all_active_sessions.values_list("session_key", flat=True)
        )

        Session.objects.filter(session_key__in=all_session_keys).delete()
        all_active_sessions.update(is_active=False)

        create_security_notification(
            user=user,
            notification_type=SecurityNotification.NOTIFICATION_TYPE_EMERGENCY_SECURITY_ACTION,
            title="Emergency security action completed",
            message="All active sessions have been revoked for your security. If this was not you, review your account activity and change your password.",
            request=request,
            session_key=current_session_key,
        )

        logout(request)
        messages.success(
            request,
            "Emergency security action completed. All sessions have been logged out. Please sign in again.",
        )
        return redirect("accounts:login")

    return render(request, "accounts/emergency_security.html")


@login_required
def login_history(request):
    """
    Display the authenticated user's login history.

    Retrieves only the current user's LoginHistory records, ordered
    by newest first, and paginates them at 20 records per page.
    Does not accept any user identifier from the URL or query string.

    Args:
        request: The HTTP request object containing the authenticated user.

    Returns:
        HttpResponse: Rendered login history template with paginated records.
    """
    history_qs = LoginHistory.objects.filter(user=request.user).order_by("-timestamp")
    paginator = Paginator(history_qs, 20)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(
        request,
        "accounts/login_history.html",
        {"page_obj": page_obj},
    )


@login_required
def security_notifications(request):
    """
    Display the authenticated user's security notifications.

    Retrieves only the current user's SecurityNotification records,
    ordered by newest first, and paginates them at 20 records per page.
    """
    notifications_qs = SecurityNotification.objects.filter(
        user=request.user
    ).order_by("-created_at")
    paginator = Paginator(notifications_qs, 20)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(
        request,
        "accounts/security_notifications.html",
        {"page_obj": page_obj},
    )


@login_required
def mark_notification_read(request, notification_id):
    """
    Mark a single security notification as read.

    Accepts only POST requests. Finds the SecurityNotification by
    primary key scoped to the current user and marks it as read.
    Redirects back to the security notifications page.
    """
    if request.method != "POST":
        return redirect("accounts:security_notifications")

    notification = get_object_or_404(
        SecurityNotification,
        id=notification_id,
        user=request.user,
    )
    notification.is_read = True
    notification.save(update_fields=["is_read"])

    messages.success(request, "Notification marked as read.")
    return redirect("accounts:security_notifications")


@login_required
def mark_all_notifications_read(request):
    """
    Mark all of the current user's security notifications as read.

    Accepts only POST requests. Updates all unread SecurityNotification
    records for request.user in a single query. Redirects back to the
    security notifications page.
    """
    if request.method != "POST":
        return redirect("accounts:security_notifications")

    SecurityNotification.objects.filter(
        user=request.user,
        is_read=False,
    ).update(is_read=True)

    messages.success(request, "All notifications marked as read.")
    return redirect("accounts:security_notifications")


def verify_email(request, uidb64, token):
    """
    Verify a user's email address using a time-limited token.

    Decodes the user ID from the URL, validates the token, sets
    is_verified=True, and redirects to the login page with a success
    message. If the token is invalid or expired, renders an error page.

    Args:
        request: The HTTP request object.
        uidb64: Base64-encoded user primary key.
        token: Email verification token.

    Returns:
        HttpResponse: Redirect to login on success, or rendered
                      invalid token template on failure.
    """
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = get_user_model().objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
        user = None

    if user is not None and email_verification_token.check_token(user, token):
        user.is_verified = True
        user.save()

        create_security_notification(
            user=user,
            notification_type=SecurityNotification.NOTIFICATION_TYPE_EMAIL_VERIFIED,
            title="Email address verified",
            message="Your email address has been verified successfully.",
            request=request,
        )

        messages.success(request, "Your email has been verified successfully. You can now log in.")
        return redirect("accounts:login")
    else:
        return render(request, "accounts/verify_email_invalid.html")


@login_required
def resend_verification(request):
    """
    Resend the email verification link to the current user.

    Only authenticated users can access this view. Generates a new
    token and sends a fresh verification email.

    Args:
        request: The HTTP request object containing the authenticated user.

    Returns:
        HttpResponse: Redirect to dashboard with a success or error message.
    """
    user = request.user
    if user.is_verified:
        messages.info(request, "Your email is already verified.")
        return redirect("accounts:dashboard")

    current_site = get_current_site(request)
    subject = "Verify your email address"
    message = render_to_string("accounts/emails/verify_email.html", {
        "user": user,
        "domain": current_site.domain,
        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
        "token": email_verification_token.make_token(user),
    })

    send_mail(
        subject=subject,
        message=message,
        from_email=None,
        recipient_list=[user.email],
        html_message=message,
    )

    messages.success(request, "A new verification email has been sent. Please check your inbox.")
    return redirect("accounts:dashboard")
