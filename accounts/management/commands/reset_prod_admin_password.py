import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Reset the production admin password and ensure admin permissions (one-time)."

    def handle(self, *args, **options):
        email = os.environ.get("PROD_ADMIN_EMAIL", "")
        password = os.environ.get("PROD_ADMIN_PASSWORD", "")

        if not email or not password:
            self.stdout.write(
                "PROD_ADMIN_EMAIL or PROD_ADMIN_PASSWORD not set. Skipping admin password reset."
            )
            return

        email = email.strip().lower()

        User = get_user_model()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            self.stderr.write(
                f"Admin user with email {email} does not exist. "
                "Ensure the superuser was created first."
            )
            raise SystemExit(1)

        user.set_password(password)
        user.is_staff = True
        user.is_superuser = True
        user.is_active = True
        user.save()

        self.stdout.write(f"Admin password reset successfully for {email}.")
