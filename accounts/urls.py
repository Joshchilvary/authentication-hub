"""
URL configuration for the accounts app.

Routes are namespaced using app_name = 'accounts' to prevent conflicts
with other apps in the project.
"""

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
]
