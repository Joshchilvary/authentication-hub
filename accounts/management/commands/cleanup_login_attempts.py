from django.core.management.base import BaseCommand
from datetime import timedelta

from django.utils import timezone

from accounts.models import LoginAttempt


class Command(BaseCommand):
    """
    Remove expired LoginAttempt records.

    Deletes records whose last_attempt_at is older than the cutoff
    and that are not currently blocked. This prevents the table from
    growing indefinitely while preserving active throttle state.
    """

    help = "Remove expired login attempt records."

    def handle(self, *args, **options):
        cutoff = timezone.now() - timedelta(days=7)

        stale_attempts = LoginAttempt.objects.filter(
            last_attempt_at__lt=cutoff,
        ).exclude(
            blocked_until__gt=timezone.now(),
        )

        count = stale_attempts.count()
        stale_attempts.delete()

        self.stdout.write(
            self.style.SUCCESS(
                f"Deleted {count} expired login attempt records."
            )
        )
