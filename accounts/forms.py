"""
Forms for the custom User model.

Provides registration and admin forms for creating and managing users
in both the frontend authentication flow and the Django admin interface.
"""

from django import forms
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.forms import UserChangeForm, UserCreationForm

from .models import User

FORM_CONTROL_CLASS = "form-control"


class RegistrationForm(UserCreationForm):
    """
    Form for user registration via the frontend.

    Extends Django's UserCreationForm to work with the custom User model
    authenticated by email. Includes custom fields for first name, last name,
    phone number, and email alongside the standard password fields.
    """

    first_name = forms.CharField(
        required=True,
        max_length=150,
        widget=forms.TextInput(
            attrs={
                "class": FORM_CONTROL_CLASS,
                "placeholder": "Enter your first name",
            }
        ),
        label="First Name",
    )
    last_name = forms.CharField(
        required=True,
        max_length=150,
        widget=forms.TextInput(
            attrs={
                "class": FORM_CONTROL_CLASS,
                "placeholder": "Enter your last name",
            }
        ),
        label="Last Name",
    )
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(
            attrs={
                "class": FORM_CONTROL_CLASS,
                "placeholder": "Enter your email address",
            }
        ),
        label="Email Address",
    )
    phone_number = forms.CharField(
        required=False,
        max_length=20,
        widget=forms.TextInput(
            attrs={
                "class": FORM_CONTROL_CLASS,
                "placeholder": "Enter your phone number",
            }
        ),
        label="Phone Number",
    )
    password1 = forms.CharField(
        label="Password",
        widget=forms.PasswordInput(
            attrs={
                "class": FORM_CONTROL_CLASS,
                "placeholder": "Create a strong password",
            }
        ),
        help_text="Your password must be at least 8 characters long.",
    )
    password2 = forms.CharField(
        label="Confirm Password",
        widget=forms.PasswordInput(
            attrs={
                "class": FORM_CONTROL_CLASS,
                "placeholder": "Confirm your password",
            }
        ),
        help_text="Enter the same password as above for verification.",
    )

    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "phone_number", "password1", "password2")

    def clean_email(self):
        """
        Normalize the email and validate uniqueness.

        Uses Django's BaseUserManager.normalize_email() for consistent
        email normalization (handles lowercase and whitespace), then
        checks case-insensitive uniqueness against existing users.
        """
        email = self.cleaned_data.get("email")
        if email:
            email = BaseUserManager.normalize_email(email.strip())
            if User.objects.filter(email__iexact=email).exists():
                raise forms.ValidationError("A user with this email address already exists.")
        return email

    def save(self, commit=True):
        """
        Create and optionally save the new user.

        Uses super().save(commit=False) to get an unsaved User instance,
        explicitly assigns all fields, and saves only when commit=True.
        Easy to extend for email verification, profile creation, or audit logging.
        """
        user = super().save(commit=False)
        user.first_name = self.cleaned_data["first_name"]
        user.last_name = self.cleaned_data["last_name"]
        user.email = self.cleaned_data["email"]
        user.phone_number = self.cleaned_data["phone_number"]
        if commit:
            user.save()
        return user


class UserAdminCreationForm(UserCreationForm):
    """
    Form used to create a new user in the Django admin.

    Inherits from UserCreationForm and is bound to the custom User model.
    """

    class Meta:
        model = User
        fields = ("email",)


class UserAdminChangeForm(UserChangeForm):
    """
    Form used to modify an existing user in the Django admin.

    Inherits from UserChangeForm and is bound to the custom User model.
    """

    class Meta:
        model = User
        fields = "__all__"