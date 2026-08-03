"""
Custom user model for the authentication hub.

This model extends Django's AbstractUser to support authentication via email
instead of the default username field, while retaining all built-in
authentication features such as permissions, groups, and session management.
"""

from django.db import models
from django.contrib.auth.models import AbstractUser

from .managers import UserManager


class User(AbstractUser):
    """
    Custom user model that extends AbstractUser for email-based authentication.

    Uses email as the unique identifier instead of the default username field,
    while preserving all default Django authentication functionality.
    """

    username = None
    email = models.EmailField(unique=True)
    phone_number = models.CharField(max_length=20, blank=True, verbose_name="Phone Number")
    profile_picture = models.ImageField(upload_to="users/profile_pictures/", blank=True, null=True, verbose_name="Profile Picture")
    bio = models.TextField(blank=True, verbose_name="Biography")
    is_verified = models.BooleanField(default=False, verbose_name="Email Verified")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Created At")
    updated_at = models.DateTimeField(auto_now=True, verbose_name="Updated At")

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        verbose_name = "User"
        verbose_name_plural = "Users"
        ordering = ["-created_at"]

    def __str__(self):
        return self.email
