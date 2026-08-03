"""
URL configuration for the accounts app.

Routes are namespaced using app_name = 'accounts' to prevent conflicts
with other apps in the project.
"""

from django.urls import path
from django.views.generic import TemplateView

from . import views

app_name = "accounts"

urlpatterns = [
    path("register/", views.register, name="register"),
    path("login/", TemplateView.as_view(template_name="accounts/login.html"), name="login"),
]
