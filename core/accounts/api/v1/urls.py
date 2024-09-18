from django.urls import include, path
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView

# Import views from the local module
from . import views

app_name = "api-v1"
# Define the URL patterns for the application
urlpatterns = [
    # URL pattern for user registration
    # Calls the RegistrationApiView from the views module
    path("registration/", views.RegistrationApiView.as_view(), name="registration"),
    # URL pattern for user login using token authentication
    # Calls the CustomObtainAuthToken from the views module
    path("token/login/", views.CustomObtainAuthToken.as_view(), name="token-login"),
    # URL pattern for user logout using token authentication
    # Calls the CustomDiscardAuthToken from the views module
    path("token/logout/", views.CustomDiscardAuthToken.as_view(), name="token-logout"),
    # URL pattern for creating JSON Web Tokens (JWT)
    # Calls the CustomTokenObtainPairView from the views module
    path("jwt/create/", views.CustomTokenObtainPairView.as_view(), name="jwt-create"),
    # URL pattern for refreshing JWT tokens
    # Calls the TokenRefreshView from rest_framework_simplejwt.views
    path("jwt/refresh/", TokenRefreshView.as_view(), name="jwt-refresh"),
    # URL pattern for verifying JWT tokens
    # Calls the TokenVerifyView from rest_framework_simplejwt.views
    path("jwt/verify/", TokenVerifyView.as_view(), name="jwt-verify"),
    # URL pattern for changing user passwords
    # Calls the ChangePasswordAPIView from the views module
    path(
        "change-password/",
        views.ChangePasswordAPIView.as_view(),
        name="change-password",
    ),
    # URL pattern for confirming user activation using an activation token
    # Calls the ActivationTokenView from the views module
    path(
        "activation/confirm/<str:token>",
        views.ActivationTokenView.as_view(),
        name="activation-confirm",
    ),
    # URL pattern for resending user activation links
    # Calls the ActivationResendTokenView from the views module
    path(
        "activation/resend/",
        views.ActivationResendTokenView.as_view(),
        name="activation-resend",
    ),
    # URL pattern for requesting password resets
    # Calls the PasswordResetRequestView from the views module
    path(
        "password-reset/",
        views.PasswordResetRequestView.as_view(),
        name="password-reset",
    ),
    # URL pattern for confirming password resets using an encoded primary key and token
    # Calls the PasswordResetConfirmView from the views module
    path(
        "password-reset-confirm/<str:encoded_pk>/<str:token>/",
        views.PasswordResetConfirmView.as_view(),
        name="password-reset-confirm",
    ),
]
