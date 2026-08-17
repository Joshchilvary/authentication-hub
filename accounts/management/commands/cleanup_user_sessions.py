from django.core.management.base import BaseCommand
from django.contrib.sessions.models import Session

from accounts.models import UserSession


class Command(BaseCommand):
    """
    Mark stale UserSession records as inactive.

    A UserSession is considered stale when its session_key no longer
    corresponds to a valid Django session in the django_session table.
    This can happen when a session expires naturally or is cleared
    outside of the normal logout flow.
    """

    help = "Mark stale UserSession records as inactive."

    def handle(self, *args, **options):
        active_sessions = UserSession.objects.filter(is_active=True)

        session_keys = list(
            active_sessions.values_list("session_key", flat=True)
        )

        if not session_keys:
            self.stdout.write("No active user sessions found.")
            return

        valid_sessions = Session.objects.filter(session_key__in=session_keys)
        valid_keys = set(valid_sessions.values_list("session_key", flat=True))

        stale_sessions = active_sessions.exclude(session_key__in=valid_keys)
        stale_count = stale_sessions.count()

        if stale_count == 0:
            self.stdout.write("No stale user sessions found.")
            return

        stale_sessions.update(is_active=False)

        self.stdout.write(
            self.style.SUCCESS(
                f"Marked {stale_count} stale user sessions as inactive."
            )
        )
