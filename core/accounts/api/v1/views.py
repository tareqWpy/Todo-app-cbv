import jwt
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError
from mail_templated import EmailMessage
from rest_framework import generics, status
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from ...models import User
from ..utils import EmailThread
from .serializers import (
    ActivationResendSerializer,
    ChangePasswordSerializer,
    CustomAuthTokenSerializer,
    CustomeTokenObtainPairSerializer,
    RegistrationSerializer,
    ResetPasswordConfirmSerializer,
    ResetPasswordRequestSerializer,
)


class RegistrationApiView(generics.GenericAPIView):
    """
    This view is responsible for handling user registration.
    It accepts POST requests with user data and creates a new user in the database.
    It also sends an activation email to the user's email address.
    """

    serializer_class = RegistrationSerializer

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests for user registration.

        Parameters:
        - request: The incoming request object containing user data.

        Returns:
        - A response object with HTTP status code 201 (Created) if the registration is successful.
        - A response object with HTTP status code 400 (Bad Request) if the registration data is invalid.
        """
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            email = serializer.validated_data["email"]
            data = {
                "email": email,
            }
            user_obj = get_object_or_404(User, email=email)
            token = self.get_tokens_for_user(user_obj)
            activation_url = reverse(
                "accounts:api-v1:activation-confirm",
                kwargs={"token": token},
            )
            activation_link = f"{request.scheme}://{request.get_host()}{activation_url}"

            email_obj = EmailMessage(
                "email/activation_email.tpl",
                {"activation_link": activation_link},
                "admin@amin.com",
                to=[email],
            )
            EmailThread(email_obj=email_obj).start()
            return Response(data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_tokens_for_user(self, user):
        """
        Generates refresh and access tokens for a given user.

        Parameters:
        - user: The user object for which tokens need to be generated.

        Returns:
        - A string representing the access token.
        """
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)


class CustomObtainAuthToken(ObtainAuthToken):
    """
    This view is responsible for obtaining an authentication token for a user.
    It accepts POST requests with user credentials and returns a token.
    """

    serializer_class = CustomAuthTokenSerializer

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests for obtaining an authentication token.

        Parameters:
        - request: The incoming request object containing user credentials.

        Returns:
        - A response object with HTTP status code 200 (OK) and the authentication token if the credentials are valid.
        """
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        token, created = Token.objects.get_or_create(user=user)
        return Response({"token": token.key, "user_id": user.pk, "email": user.email})


class CustomDiscardAuthToken(APIView):
    """
    This view is responsible for discarding an authentication token for a user.
    It accepts POST requests and deletes the token associated with the user.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        """
        Handles POST requests for discarding an authentication token.

        Parameters:
        - request: The incoming request object containing the user's authentication token.

        Returns:
        - A response object with HTTP status code 204 (No Content) if the token is successfully discarded.
        """
        request.user.auth_token.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    This view is responsible for obtaining a refresh and access token pair for a user.
    It accepts POST requests with user credentials and returns a pair of tokens.
    """

    serializer_class = CustomeTokenObtainPairSerializer


class ChangePasswordAPIView(generics.GenericAPIView):
    """
    This view is responsible for changing a user's password.
    It accepts PUT requests with the old and new passwords and updates the user's password in the database.
    """

    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = [IsAuthenticated]

    def get_object(self, queryset=None):
        """
        Retrieves the user object for the current request.

        Returns:
        - The user object associated with the current request.
        """
        obj = self.request.user
        return obj

    def put(self, request, *args, **kwargs):
        """
        Handles PUT requests for changing a user's password.

        Parameters:
        - request: The incoming request object containing the old and new passwords.

        Returns:
        - A response object with HTTP status code 200 (OK) if the password is successfully changed.
        - A response object with HTTP status code 400 (Bad Request) if the old password is incorrect.
        """
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response(
                    {"old_password": ["Wrong password."]},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            return Response(
                {"details": "password changed successfully"}, status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ActivationTokenView(APIView):
    """
    This view is responsible for verifying a user's account using an activation token.
    It accepts GET requests with an activation token and updates the user's account status in the database.
    """

    def get(self, request, token, *args, **kwargs):
        """
        Handles GET requests for verifying a user's account using an activation token.

        Parameters:
        - request: The incoming request object containing the activation token.
        - token: The activation token provided in the request.

        Returns:
        - A response object with HTTP status code 200 (OK) if the account is successfully verified and activated.
        - A response object with HTTP status code 400 (Bad Request) if the token is invalid or expired.
        """
        try:
            token = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
            user_id = token.get("user_id")
        except ExpiredSignatureError:
            return Response(
                {"details": "Token expired"}, status=status.HTTP_400_BAD_REQUEST
            )
        except InvalidSignatureError:
            return Response(
                {"details": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST
            )
        user_obj = User.objects.get(pk=user_id)
        if user_obj.is_verified:
            return Response(
                {"details": "your account is already verified"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user_obj.is_verified = True
        user_obj.save()
        user_obj.refresh_from_db()
        return Response(
            {"details": "your account have been verified and activated successfully"},
            status=status.HTTP_200_OK,
        )


class ActivationResendTokenView(generics.GenericAPIView):
    """
    This view is responsible for resending an activation email to a user.
    It accepts POST requests with the user's email address and sends a new activation email to the user.
    """

    serializer_class = ActivationResendSerializer

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests for resending an activation email.

        Parameters:
        - request: The incoming request object containing the user's email address.

        Returns:
        - A response object with HTTP status code 200 (OK) if the activation email is successfully resent.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_obj = serializer.validated_data["user"]
        token = self.get_tokens_for_user(user_obj)
        activation_url = reverse(
            "accounts:api-v1:activation-confirm",
            kwargs={"token": token},
        )
        activation_link = f"{request.scheme}://{request.get_host()}{activation_url}"

        email_obj = EmailMessage(
            "email/activation_email.tpl",
            {"activation_link": activation_link},
            "admin@amin.com",
            to=[user_obj.email],
        )
        EmailThread(email_obj=email_obj).start()
        return Response(
            {"dtails": "user activation resend successfully"},
            status=status.HTTP_200_OK,
        )

    def get_tokens_for_user(self, user):
        """
        Generates refresh and access tokens for a given user.

        Parameters:
        - user: The user object for which tokens need to be generated.

        Returns:
        - A string representing the access token.
        """
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)


class PasswordResetRequestView(generics.GenericAPIView):
    """
    This view is responsible for initiating a password reset process for a user.
    It accepts POST requests with the user's email address and sends a password reset email to the user.
    """

    serializer_class = ResetPasswordRequestSerializer

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests for initiating a password reset process.

        Parameters:
        - request: The incoming request object containing the user's email address.

        Returns:
        - A response object with HTTP status code 200 (OK) if the password reset email is successfully sent.
        """
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_obj = serializer.validated_data["user"]

        if user_obj:
            encoded_pk = urlsafe_base64_encode(force_bytes(user_obj.pk))
            token = PasswordResetTokenGenerator().make_token(
                user=user_obj,
            )
            reset_url = reverse(
                "accounts:api-v1:password-reset-confirm",
                kwargs={"encoded_pk": encoded_pk, "token": token},
            )
            reset_link = f"{request.scheme}://{request.get_host()}{reset_url}"

            email_obj = EmailMessage(
                "email/password_reset.tpl",
                {"reset_link": reset_link},
                "admin@amin.com",
                to=[user_obj.email],
            )
            EmailThread(email_obj=email_obj).start()
            return Response(
                {"details": "Password reset email sent successfully."},
                status=status.HTTP_200_OK,
            )


class PasswordResetConfirmView(generics.GenericAPIView):
    """
    This view is responsible for confirming a password reset request for a user.
    It accepts POST requests with the new password and updates the user's password in the database.
    """

    serializer_class = ResetPasswordConfirmSerializer

    def post(self, request, *args, **kwargs):
        """
        Handles POST requests for confirming a password reset request.

        Parameters:
        - request: The incoming request object containing the new password.
        - kwargs: Additional keyword arguments containing the encoded primary key and token.

        Returns:
        - A response object with HTTP status code 200 (OK) if the password reset is successfully completed.
        """
        serializer = self.serializer_class(
            data=request.data, context={"kwargs": kwargs}
        )
        serializer.is_valid(raise_exception=True)
        return Response(
            {"details": "Password reset complete."},
            status=status.HTTP_200_OK,
        )
