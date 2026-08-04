"""
Views for the accounts app.

Handles user registration, authentication, dashboard, and logout
using the custom User model with email-based login via Django's
authentication system.
"""

from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect

from .forms import LoginForm, RegistrationForm


def register(request):
    """
    Handle user registration.

    On GET: Display an empty registration form.
    On POST: Validate the submitted form, create a new user if valid,
             and redirect to the login page with a success message.

    Returns:
        HttpResponse: Rendered registration template or redirect to login.
    """
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, "Your account has been created successfully. Please log in.")
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

    redirect_url = request.GET.get("next", "accounts:dashboard")

    if request.method == "POST":
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, "You have been logged in successfully.")
            return redirect(redirect_url)
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
