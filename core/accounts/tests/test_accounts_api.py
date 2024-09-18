from datetime import datetime, timedelta

import jwt
import pytest
from accounts.models import User
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken


@pytest.fixture
def api_client():
    """
    Returns an instance of APIClient for testing API endpoints.
    """
    client = APIClient()
    return client


@pytest.fixture
def unverified_user():
    """Creates a unverified test user."""
    user = User.objects.create_user(
        email="testuser@example.com", password="TestPassword123!"
    )
    return user


@pytest.fixture
def verified_user():
    """Creates a verified test user."""
    user = User.objects.create_user(
        email="testuser@example.com", password="TestPassword123!", is_verified=True
    )
    return user


@pytest.fixture
def verified_user_with_auth_token(api_client, verified_user):
    """Creates a verified test user and assigns a token."""
    user = verified_user
    response = api_client.post(
        reverse("accounts:api-v1:token-login"),
        {"email": user.email, "password": "TestPassword123!"},
    )
    token = response.data["token"]
    return user, token


@pytest.fixture
def verified_user_with_token_for_password_reset(api_client, verified_user):
    """Creates a verified test user and assigns a token for password reset."""
    url = reverse("accounts:api-v1:password-reset")
    response = api_client.post(url, {"email": verified_user.email})
    assert response.status_code == status.HTTP_200_OK, "Password reset request failed"

    token = PasswordResetTokenGenerator().make_token(verified_user)
    encoded_pk = urlsafe_base64_encode(force_bytes(verified_user.pk))

    reset_confirm_url = reverse(
        "accounts:api-v1:password-reset-confirm",
        kwargs={"encoded_pk": encoded_pk, "token": token},
    )

    return verified_user, reset_confirm_url


@pytest.fixture
def verified_user_with_expired_token_for_password_reset(api_client, verified_user):
    """Creates a verified test user and assigns an expired token for password reset."""

    url = reverse("accounts:api-v1:password-reset")
    response = api_client.post(url, {"email": verified_user.email})
    assert response.status_code == status.HTTP_200_OK, "Password reset request failed"

    expired_token = "invalid_or_expired_token"
    encoded_pk = urlsafe_base64_encode(force_bytes(verified_user.pk))

    reset_confirm_url = reverse(
        "accounts:api-v1:password-reset-confirm",
        kwargs={"encoded_pk": encoded_pk, "token": expired_token},
    )

    return verified_user, reset_confirm_url


@pytest.fixture
def create_expired_token(unverified_user):
    """
    Creates an expired JWT token for the given user.
    """
    secret_key = settings.SECRET_KEY
    payload = {
        "user_id": unverified_user.id,
        "exp": datetime.now(),  # for instant expiration
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")


@pytest.fixture
def create_invalid_token(unverified_user):
    """Creates an invalid JWT token for the given user."""
    secret_key = "not_secret_key"  # for creating invalid token
    payload = {
        "user_id": unverified_user.id,
        "exp": datetime.now() - timedelta(seconds=3600),
    }
    return jwt.encode(payload, secret_key, algorithm="HS256")


@pytest.mark.django_db
class TestAccountsAPI:
    """A class for testing accounts views and urls API"""

    def test_registeration_201_status(self, api_client):
        """Testing Registration."""

        url = reverse("accounts:api-v1:registration")
        data = {
            "email": "newuser@example.com",
            "password": "TestPassword123!",
            "password1": "TestPassword123!",
        }
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data["email"] == "newuser@example.com"

    def test_registration_email_already_exists_400_status(
        self, api_client, unverified_user
    ):
        """Testing Registration with an existing email."""

        url = reverse("accounts:api-v1:registration")
        data = {
            "email": "testuser@example.com",
            "password": "TestPassword123!",
            "password1": "TestPassword123!",
        }
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "email" in response.data

    def test_change_password_200_status(self, api_client, unverified_user):
        """Testing Change Password."""

        api_client.force_authenticate(user=unverified_user)
        url = reverse("accounts:api-v1:change-password")
        data = {
            "old_password": "TestPassword123!",
            "new_password": "NewTestPassword456!",
            "new_password1": "NewTestPassword456!",
        }
        response = api_client.put(url, data)
        assert response.status_code == status.HTTP_200_OK
        assert response.data["details"] == "password changed successfully"
        unverified_user.refresh_from_db()
        assert unverified_user.check_password("NewTestPassword456!") is True

    def test_change_password_wrong_old_password_400_status(
        self, api_client, unverified_user
    ):
        """Testing Change Password with a wrong old password."""

        api_client.force_authenticate(user=unverified_user)
        url = reverse("accounts:api-v1:change-password")
        data = {
            "old_password": "WrongOldPassword",
            "new_password": "NewTestPassword456!",
            "new_password1": "NewTestPassword456!",
        }
        response = api_client.put(url, data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "old_password" in response.data

    def test_obtain_auth_token_200_status(self, api_client, verified_user):
        """Testing obtaining auth token for verified user."""

        url = reverse("accounts:api-v1:token-login")
        data = {"email": "testuser@example.com", "password": "TestPassword123!"}
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_200_OK
        assert "token" in response.data
        assert response.data["email"] == "testuser@example.com"

    def test_obtain_auth_token_unverified_user_400_status(
        self, api_client, unverified_user
    ):
        """Testing obtaining auth token for unverified user."""

        url = reverse("accounts:api-v1:token-login")
        data = {"email": "testuser@example.com", "password": "TestPassword123!"}
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_obtain_auth_token_invalid_credentials_400_status(self, api_client):
        """Testing obtaining auth token with wrong inputs."""

        url = reverse("accounts:api-v1:token-login")
        data = {"email": "nonexistent@example.com", "password": "WrongPassword"}
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert "non_field_errors" in response.data

    def test_discard_auth_token_verified_user_204_status(
        self, api_client, verified_user_with_auth_token
    ):
        """Testing dicarding auth token for verified user with auth_token."""

        user, token = verified_user_with_auth_token
        api_client.credentials(HTTP_AUTHORIZATION="Token " + token)
        url = reverse("accounts:api-v1:token-logout")
        response = api_client.post(url)
        assert response.status_code == status.HTTP_204_NO_CONTENT
        assert not hasattr(user, "auth_token")

    def test_discard_auth_token_not_authenticated_401_status(self, api_client):
        """Testing obtaining auth token for unathorized user."""

        url = reverse("accounts:api-v1:token-logout")
        response = api_client.post(url)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_activation_already_verified_400_status(self, api_client, verified_user):
        """Testing activation for verified user with JWT."""

        payload = {"user_id": verified_user.id}
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")
        url = reverse("accounts:api-v1:activation-confirm", kwargs={"token": token})

        response = api_client.get(url)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data == {"details": "your account is already verified"}

    def test_jwt_refresh_200_status(self, api_client, verified_user):
        """Testing JWT refresh endpoint."""

        refresh = RefreshToken.for_user(verified_user)
        url = reverse("accounts:api-v1:jwt-refresh")

        response = api_client.post(url, {"refresh": str(refresh)})

        assert response.status_code == status.HTTP_200_OK
        assert "access" in response.data

    def test_jwt_verify_200_status(self, api_client, verified_user):
        """Testing JWT verify endpoint."""

        # Obtain a token for the verified user
        access_token = RefreshToken.for_user(verified_user).access_token
        url = reverse("accounts:api-v1:jwt-verify")

        response = api_client.post(url, {"token": str(access_token)})

        assert response.status_code == status.HTTP_200_OK

    def test_jwt_refresh_invalid_token_401_status(self, api_client, verified_user):
        """Testing JWT refresh with invalid token."""

        url = reverse("accounts:api-v1:jwt-refresh")
        response = api_client.post(url, {"refresh": "invalid-token"})

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert (
            response.data["detail"] == "token_not_valid",
            "token_not_valid",
        )

    def test_jwt_verify_invalid_token_401_status(self, api_client):
        """Testing JWT verify with invalid token."""

        url = reverse("accounts:api-v1:jwt-verify")
        response = api_client.post(url, {"token": "invalid-token"})

        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        assert (
            response.data["detail"] == "token_not_valid",
            "token_not_valid",
        )

    def test_activation_token_expired_400_status(
        self, api_client, unverified_user, create_expired_token
    ):
        """Testing activation for unverified user with expired token."""

        expired_token = create_expired_token
        url = reverse(
            "accounts:api-v1:activation-confirm", kwargs={"token": expired_token}
        )

        response = api_client.get(url)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data == {"details": "Token expired"}

    def test_activation_token_invalid_400_status(
        self, api_client, unverified_user, create_invalid_token
    ):
        """Testing activation for unverified user with invalid token."""

        invalid_token = create_invalid_token
        url = reverse(
            "accounts:api-v1:activation-confirm", kwargs={"token": invalid_token}
        )

        response = api_client.get(url)
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data == {"details": "Invalid token"}

    def test_resend_activation_200_status(self, api_client, unverified_user):
        """Testing resend activation for unverified user."""

        url = reverse("accounts:api-v1:activation-resend")
        data = {"email": unverified_user.email}
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_200_OK
        assert response.data == {"dtails": "user activation resend successfully"}

    def test_resend_activation_failure_user_not_found_400_status(self, api_client):
        """Testing activation for verified user with invalid email."""

        url = reverse("accounts:api-v1:activation-resend")
        data = {"email": "nonexistentuser@example.com"}
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_password_reset_request_200_status(self, api_client, verified_user):
        """Testing reset password for verified user."""

        url = reverse("accounts:api-v1:password-reset")
        data = {"email": verified_user.email}
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_200_OK
        assert response.data == {"details": "Password reset email sent successfully."}

    def test_password_reset_request_user_not_found_400_status(self, api_client):
        """Testing reset password with invalid email."""

        url = reverse("accounts:api-v1:password-reset")
        data = {"email": "nonexistentuser@example.com"}
        response = api_client.post(url, data)
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_password_reset_confirm_200_status(
        self, api_client, verified_user_with_token_for_password_reset
    ):
        """Testing password reset confirmation."""
        user, reset_confirm_url = verified_user_with_token_for_password_reset
        response = api_client.post(
            reset_confirm_url,
            {"new_password": "new_password123", "confirm_password": "new_password123"},
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data["details"] == "Password reset complete."
        user.refresh_from_db()
        assert user.check_password("new_password123")

    def test_password_reset_confirm_token_invalid_400_status(
        self, api_client, verified_user_with_expired_token_for_password_reset
    ):
        """Testing password reset confirmation with invalid token."""
        user, reset_confirm_url = verified_user_with_expired_token_for_password_reset

        response = api_client.post(
            reset_confirm_url,
            {"new_password": "new_password123", "confirm_password": "new_password123"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert (
            response.data["details"] == "The reset token is invalid or has expired.",
            "invalid",
        )

    def test_password_reset_confirm_password_mismatch_400_status(
        self, api_client, verified_user_with_token_for_password_reset
    ):
        """Testing password reset confirm with password mismatch."""

        user, reset_confirm_url = verified_user_with_token_for_password_reset
        response = api_client.post(
            reset_confirm_url,
            {"new_password": "new_password123", "confirm_password": "wrong_password"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert (
            response.data["details"] == "Passwords must match.",
            "invalid",
        )
