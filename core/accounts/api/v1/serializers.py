from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core import exceptions
from django.utils.http import urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

from ...models import User


class RegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.

    Attributes:
    password1 (CharField): The password entered by the user.
    """

    password1 = serializers.CharField(max_length=255, write_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "password1"]

    def validate(self, attrs):
        """
        Validates the password and ensures it matches the confirmation password.

        Args:
        attrs (dict): The attributes to be validated.

        Returns:
        dict: The validated attributes.

        Raises:
        ValidationError: If the passwords do not match or if the password does not meet the requirements.
        """
        if attrs.get("password") != attrs.get("password1"):
            raise serializers.ValidationError({"details": "Passwords must match."})
        try:
            validate_password(attrs.get("password"))
        except exceptions.ValidationError as e:
            raise serializers.ValidationError({"password": list(e.messages)})
        return super().validate(attrs)

    def create(self, validated_data):
        """
        Creates a new user with the validated data.

        Args:
        validated_data (dict): The validated attributes.

        Returns:
        User: The newly created user.
        """
        validated_data.pop("password1", None)
        return User.objects.create_user(**validated_data)


class CustomAuthTokenSerializer(serializers.Serializer):
    """
    Serializer for custom authentication token generation.
    """

    email = serializers.CharField(label=_("Email"), write_only=True)
    password = serializers.CharField(
        label=_("Password"),
        style={"input_type": "password"},
        trim_whitespace=False,
        write_only=True,
    )
    token = serializers.CharField(label=_("Token"), read_only=True)

    def validate(self, attrs):
        """
        Validates the email and password, and checks if the user is verified.

        Args:
        attrs (dict): The attributes to be validated.

        Returns:
        dict: The validated attributes.

        Raises:
        ValidationError: If the email and password do not match, or if the user is not verified.
        """
        username = attrs.get("email")
        password = attrs.get("password")

        if username and password:
            user = authenticate(
                request=self.context.get("request"),
                username=username,
                password=password,
            )

            # The authenticate call simply returns None for is_active=False
            # users. (Assuming the default ModelBackend authentication
            # backend.)
            if not user:
                msg = _("Unable to log in with provided credentials.")
                raise serializers.ValidationError(msg, code="authorization")
            if not user.is_verified:
                raise serializers.ValidationError({"details": "user is not verified"})
        else:
            msg = _('Must include "username" and "password".')
            raise serializers.ValidationError(msg, code="authorization")

        attrs["user"] = user
        return attrs


class CustomeTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Serializer for custom token pair generation.
    """

    def validate(self, attrs):
        """
        Validates the token pair and checks if the user is verified.

        Args:
        attrs (dict): The attributes to be validated.

        Returns:
        dict: The validated attributes.

        Raises:
        ValidationError: If the user is not verified.
        """
        validated_data = super().validate(attrs)
        if not self.user.is_verified:
            raise serializers.ValidationError({"details": "user is not verified"})
        validated_data["email"] = self.user.email
        validated_data["user_id"] = self.user.id
        return validated_data


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for changing the user's password.
    """

    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    new_password1 = serializers.CharField(required=True)

    def validate(self, attrs):
        """
        Validates the new password and ensures it matches the confirmation password.

        Args:
        attrs (dict): The attributes to be validated.

        Returns:
        dict: The validated attributes.

        Raises:
        ValidationError: If the passwords do not match or if the password does not meet the requirements.
        """
        if attrs.get("new_password") != attrs.get("new_password1"):
            raise serializers.ValidationError({"details": "Passwords must match."})
        try:
            validate_password(attrs.get("new_password"))
        except exceptions.ValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)})
        return super().validate(attrs)


class ActivationResendSerializer(serializers.Serializer):
    """
    Serializer for resending the activation email.
    """

    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        """
        Validates the email and checks if the user is already verified.

        Args:
        attrs (dict): The attributes to be validated.

        Returns:
        dict: The validated attributes.

        Raises:
        ValidationError: If the user does not exist or if the user is already verified.
        """
        email = attrs.get("email")
        try:
            user_obj = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"details": "user does not exist."})

        if user_obj.is_verified:
            raise serializers.ValidationError(
                {"details": "user is already verified and activated."}
            )
        attrs["user"] = user_obj
        return super().validate(attrs)


class ResetPasswordRequestSerializer(serializers.Serializer):
    """
    Serializer for requesting a password reset email.
    """

    email = serializers.EmailField(required=True)

    def validate(self, attrs):
        """
        Validates the email and checks if the user exists.

        Args:
        attrs (dict): The attributes to be validated.

        Returns:
        dict: The validated attributes.

        Raises:
        ValidationError: If the user does not exist.
        """
        email = attrs.get("email")
        try:
            user_obj = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"details": "user does not exist."})

        attrs["user"] = user_obj
        return super().validate(attrs)


class ResetPasswordConfirmSerializer(serializers.Serializer):
    """
    Serializer for confirming a password reset.
    """

    new_password = serializers.CharField(max_length=255, write_only=True, required=True)
    confirm_password = serializers.CharField(
        max_length=255, write_only=True, required=True
    )

    def validate(self, attrs):
        """
        Validates the new password, ensures it matches the confirmation password,
        and checks if the reset token is valid.

        Args:
        attrs (dict): The attributes to be validated.

        Returns:
        dict: The validated attributes.

        Raises:
        ValidationError: If the passwords do not match, if the reset token is invalid or has expired, or if the required data is missing.
        """
        token = self.context.get("kwargs").get("token")
        encoded_pk = self.context.get("kwargs").get("encoded_pk")

        if attrs.get("new_password") != attrs.get("confirm_password"):
            raise serializers.ValidationError({"details": "Passwords must match."})

        if token is None or encoded_pk is None:
            raise serializers.ValidationError({"details": "Missing data."})

        try:
            validate_password(attrs.get("new_password"))
        except exceptions.ValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)})

        pk = urlsafe_base64_decode(encoded_pk).decode()

        user = User.objects.get(pk=pk)

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise serializers.ValidationError(
                {"details": "The reset token is invalid or has expired."}
            )

        user.set_password(attrs.get("new_password"))
        user.save()

        return super().validate(attrs)
