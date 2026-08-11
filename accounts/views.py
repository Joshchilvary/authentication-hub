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
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.urls import reverse_lazy
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode, url_has_allowed_host_and_scheme

from .forms import LoginForm, ProfileUpdateForm, RegistrationForm
from .tokens import email_verification_token


class CustomPasswordResetView(PasswordResetView):
    """
    Custom password reset view.

    Uses Django's built-in PasswordResetView with custom templates
    for the form and email. Ensures the user is not logged in during
    the reset process and does not reveal whether an email exists.
    """

    template_name = "accounts/password_reset.html"
    email_template_name = "accounts/emails/password_reset_email.html"
    subject_template_name = "accounts/emails/password_reset_subject.txt"
    success_url = reverse_lazy("accounts:password_reset_done")


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
    """

    template_name = "accounts/password_reset_confirm.html"
    success_url = reverse_lazy("accounts:password_reset_complete")


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
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            remember_me = form.cleaned_data.get("remember_me")
            login(request, user)
            if not remember_me:
                request.session.set_expiry(0)
            messages.success(request, "You have been logged in successfully.")
            return redirect(redirect_url or "accounts:dashboard")
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

    Only authenticated users can access this view. If a user is not
    authenticated, Django's @login_required decorator automatically
    redirects them to the login page.

    Args:
        request: The HTTP request object for the currently authenticated user.

    Returns:
        HttpResponseRedirect: Redirect to the login page with a success message.
    """
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect("accounts:login")


@login_required
def profile(request):
    """
    Display the authenticated user's profile information.

    Only authenticated users can access this view. If a user is not
    authenticated, Django's @login_required decorator automatically
    redirects them to the login page.

    Uses request.user to avoid an unnecessary database query since the
    user is already available in the request object after authentication.

    Args:
        request: The HTTP request object containing the authenticated user.

    Returns:
        HttpResponse: Rendered profile template with the user object.
    """
    return render(request, "accounts/profile.html", {"user": request.user})


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
        display a success message, and redirect to the profile page.
        """
        user = form.save()
        update_session_auth_hash(self.request, user)
        messages.success(self.request, "Your password has been changed successfully.")
        return super().form_valid(form)


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
