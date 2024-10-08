from accounts.views import CustomLoginView, RegisterPage
from django.contrib.auth.views import LogoutView
from django.urls import include, path

# The application name
app_name = "accounts"
"""
Important urls for account management.
"""

urlpatterns = [
    # ? Commented out URL pattern for the login view (uncomment to use)
    path("login/", CustomLoginView.as_view(), name="login"),
    # ? Commented out URL pattern for the logout view with a redirect to the home page (uncomment to use)
    path("logout/", LogoutView.as_view(next_page="/"), name="logout"),
    # ? Commented out URL pattern for the registration view (uncomment to use)
    path("register/", RegisterPage.as_view(), name="register"),
    # ? Include Django's built-in authentication URLs
    path("", include("django.contrib.auth.urls")),
    # ? Include URL patterns for the API v1
    path("api/v1/", include("accounts.api.v1.urls")),
    # ? Commented out URL patterns for API v2 (uncomment to use)
    # path("api/v2/", include("djoser.urls")),
    # path("api/v2/", include("djoser.urls.jwt")),
]
