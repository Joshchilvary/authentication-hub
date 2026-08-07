"""
URL configuration for the accounts app.

Routes are namespaced using app_name = 'accounts' to prevent conflicts
with other apps in the project.
"""

from django.contrib.auth import views as auth_views
from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("register/", views.register, name="register"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("profile/", views.profile, name="profile"),
    path("profile/edit/", views.edit_profile, name="edit_profile"),
    path("password/change/", views.CustomPasswordChangeView.as_view(), name="password_change"),
    path("settings/", views.settings_view, name="settings"),
    path("verify-email/<uidb64>/<token>/", views.verify_email, name="verify_email"),
    path("resend-verification/", views.resend_verification, name="resend_verification"),
    path("password/reset/", views.CustomPasswordResetView.as_view(), name="password_reset"),
    path("password/reset/done/", views.CustomPasswordResetDoneView.as_view(), name="password_reset_done"),
    path("password/reset/<uidb64>/<token>/", views.CustomPasswordResetConfirmView.as_view(), name="password_reset_confirm"),
    path("password/reset/complete/", views.CustomPasswordResetCompleteView.as_view(), name="password_reset_complete"),
]
