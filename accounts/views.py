"""
Views for the accounts app.

Handles user registration functionality using the custom User model.
"""

from django.contrib import messages
from django.shortcuts import render, redirect

from .forms import RegistrationForm


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
