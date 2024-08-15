from django.urls import path
from accounts.views import CustomLoginView, RegisterPage

from django.contrib.auth.views import LogoutView

app_name = "accounts"
"""
Important urls for account management.
"""
urlpatterns = [
    path("login/", CustomLoginView.as_view(), name="login"),
    path("logout", LogoutView.as_view(next_page="/"), name="logout"),
    path("register/", RegisterPage.as_view(), name="register"),
]
