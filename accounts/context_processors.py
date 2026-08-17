from .models import SecurityNotification


def unread_notification_count(request):
    """
    Add the current user's unread security notification count to the
    template context.

    Only authenticated users receive the count. Anonymous users
    receive an empty context variable to avoid unnecessary queries.
    """
    if request.user.is_authenticated:
        count = SecurityNotification.objects.filter(
            user=request.user,
            is_read=False,
        ).count()
        return {"unread_notification_count": count}
    return {"unread_notification_count": 0}
