from django.apps import AppConfig


class AccountsConfig(AppConfig):
    """
    Custom Django application configuration for the 'accounts' app.

    This class extends the base AppConfig class provided by Django,
    allowing for additional customization of the 'accounts' app.

    Attributes:
    - default_auto_field: Specifies the default auto-field for models in the 'accounts' app.
        Default is 'django.db.models.BigAutoField'.
    - name: Specifies the name of the Django application.
        Default is 'accounts'.
    """

    default_auto_field = "django.db.models.BigAutoField"
    name = "accounts"
