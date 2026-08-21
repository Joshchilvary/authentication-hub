"""
Temporary admin promotion view.

Provides a one-time mechanism to promote an existing user to Django
superuser/admin status using a secret token from environment variables.
"""

import os

import secrets

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.shortcuts import render, redirect


User = get_user_model()


def temporary_admin_setup(request):
    """
    Temporary admin promotion endpoint.

    Requires TEMP_ADMIN_SETUP_TOKEN environment variable.
    Promotes an existing user to superuser/admin when valid token
    and existing email are provided.
    """
    expected_token = os.environ.get("TEMP_ADMIN_SETUP_TOKEN", "")

    if request.method == "POST":
        email = request.POST.get("email", "")
        token = request.POST.get("token", "")

        if not expected_token:
            messages.error(
                request,
                "Admin setup is not configured on this server.",
            )
            return redirect("accounts:login")

        if not secrets.compare_digest(token, expected_token):
            messages.error(
                request,
                "Invalid setup token.",
            )
            return redirect("accounts:temporary_admin_setup")

        if not email:
            messages.error(
                request,
                "Please enter an email address.",
            )
            return redirect("accounts:temporary_admin_setup")

        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            messages.error(
                request,
                "No account was found with that email address.",
            )
            return redirect("accounts:temporary_admin_setup")

        user.is_staff = True
        user.is_superuser = True
        user.is_active = True
        user.save()

        messages.success(
            request,
            "Account promoted successfully. You can now log in to the admin dashboard.",
        )
        return redirect("admin:index")

    return render(request, "accounts/temporary_admin_setup.html")
