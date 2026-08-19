from django.urls import path
from . import views

app_name = "api"

urlpatterns = [
    path("", views.api_root, name="root"),
    path("health/", views.health_check, name="health"),
    path("me/", views.current_user, name="current_user"),
    path("profile/", views.profile, name="profile"),
    path("login-history/", views.login_history, name="login_history"),
    path("sessions/", views.active_sessions, name="active_sessions"),
    path("sessions/<int:session_id>/revoke/", views.revoke_session, name="revoke_session"),
    path("sessions/logout-others/", views.logout_other_sessions, name="logout_other_sessions"),
    path("notifications/", views.notifications, name="notifications"),
    path("notifications/<int:notification_id>/read/", views.mark_notification_read, name="mark_notification_read"),
    path("notifications/read-all/", views.mark_all_notifications_read, name="mark_all_notifications_read"),
    path("risk-assessments/", views.risk_assessments, name="risk_assessments"),
    path("auth/token/", views.jwt_token_obtain_pair, name="token_obtain_pair"),
    path("auth/token/refresh/", views.jwt_token_refresh, name="token_refresh"),
    path("auth/token/verify/", views.jwt_token_verify, name="token_verify"),
    path("auth/logout/", views.jwt_logout, name="jwt_logout"),
    path("schema/", views.openapi_schema, name="schema"),
    path("docs/", views.swagger_docs, name="swagger_docs"),
    path("redoc/", views.redoc_docs, name="redoc_docs"),
]
