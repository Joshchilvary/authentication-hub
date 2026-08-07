from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode


class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    """
    Token generator for email verification.

    Extends Django's PasswordResetTokenGenerator to create time-limited
    tokens specifically for verifying a user's email address. The token
    is bound to the user's primary key, email, and is_verified status,
    so it automatically becomes invalid after verification.
    """

    def _make_hash_value(self, user, timestamp):
        """
        Include the user's email and verification status in the hash so
        the token becomes invalid once the email is verified.
        """
        login_timestamp = user.last_login or user.created_at if hasattr(user, 'created_at') else ''
        return (
            str(user.pk) + str(timestamp) +
            str(user.email) + str(user.is_verified) +
            str(login_timestamp)
        )


email_verification_token = EmailVerificationTokenGenerator()
