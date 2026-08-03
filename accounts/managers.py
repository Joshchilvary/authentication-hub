"""
Custom user manager for the authentication hub.
This manager extends BaseUserManager to provide user creation functionality
using email as the primary identifier instead of the default username.
"""

from django.contrib.auth.models import BaseUserManager


class UserManager(BaseUserManager):
    """
    Custom user manager that uses email for authentication.

    Extends Django's BaseUserManager to support email-based user creation,
    providing create_user and create_superuser methods with appropriate
    validation.
    """

    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """
        Create and save a user with the given email and password.

        Args:
            email: The user's email address.
            password: The user's password.
            **extra_fields: Additional fields to pass to the user model.

        Returns:
            The created User instance.

        Raises:
            ValueError: If email is not provided.
        """
        if not email:
            raise ValueError("The given email must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """
        Create a regular user with the given email and password.

        Args:
            email: The user's email address.
            password: The user's password. Defaults to None.
            **extra_fields: Additional fields to pass to the user model.

        Returns:
            The created User instance with standard permissions.
        """
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        extra_fields.setdefault("is_active", True)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create a superuser with the given email and password.

        Args:
            email: The superuser's email address.
            password: The superuser's password. Defaults to None.
            **extra_fields: Additional fields to pass to the user model.

        Returns:
            The created superuser User instance.

        Raises:
            ValueError: If is_staff or is_superuser is not True.
        """
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True")

        return self._create_user(email, password, **extra_fields)
