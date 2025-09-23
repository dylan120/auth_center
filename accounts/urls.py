"""
accounts urls
"""

from django.urls import path

from . import views

urlpatterns = [
    path("api/auth/login/", views.LoginView.as_view(), name="login"),
    path("api/auth/logout/", views.logout_view, name="logout"),
    path("api/auth/current-user/", views.current_user_view, name="current_user"),
]
