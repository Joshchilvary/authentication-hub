import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Create a production superuser from environment variables (idempotent)."

    def handle(self, *args, **options):
        email = os.environ.get("PROD_SUPERUSER_EMAIL", "")
        password = os.environ.get("PROD_SUPERUSER_PASSWORD", "")

        if not email or not password:
            self.stdout.write(
                "PROD_SUPERUSER_EMAIL or PROD_SUPERUSER_PASSWORD not set. Skipping superuser creation."
            )
            return

        email = email.strip().lower()

        User = get_user_model()
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "is_staff": True,
                "is_superuser": True,
                "is_active": True,
            },
        )

        if created:
            user.set_password(password)
            user.save()
            self.stdout.write(f"Superuser {email} created successfully.")
        else:
            updated = False
            if not user.is_staff:
                user.is_staff = True
                updated = True
            if not user.is_superuser:
                user.is_superuser = True
                updated = True
            if not user.is_active:
                user.is_active = True
                updated = True

            if updated:
                user.save()
                self.stdout.write(f"Updated existing user {email} to superuser.")
            else:
                self.stdout.write(f"Superuser {email} already exists and has correct permissions.")
