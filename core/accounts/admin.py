from accounts.models import User
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.forms import UserCreationForm


class CustomUserCreationForm(UserCreationForm):
    """
    A class for Custom Form.
    """

    class Meta:
        model = User
        fields = ("email",)


class CustomUserAdmin(UserAdmin):
    """
    A class for presenting the Custom User models data in Admin panel.
    """

    model = User
    add_form = CustomUserCreationForm
    list_display = (
        "email",
        "is_superuser",
        "is_active",
        "is_verified",
    )
    list_filter = ("email", "is_active")
    serching_fields = ("email",)
    ordering = ("email",)

    """
    The presented fileds in Admin panel.
    """
    fieldsets = (
        (
            "Authentication",
            {
                "fields": (
                    "email",
                    "password",
                ),
            },
        ),
        (
            "Permissions",
            {
                "fields": (
                    "is_staff",
                    "is_active",
                    "is_superuser",
                    "is_verified",
                ),
            },
        ),
        (
            "Group Permissions",
            {
                "fields": (
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (
            "Important Dates",
            {
                "fields": ("last_login",),
            },
        ),
    )

    """
    Important fiedls for Adding a user based on Django User model.
    """
    add_fieldsets = (
        (
            "None",
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "password1",
                    "password2",
                    "is_staff",
                    "is_active",
                    "is_superuser",
                    "is_verified",
                ),
            },
        ),
    )


"""
Registeration for Admin panel to present data of Users.
"""
admin.site.register(User, CustomUserAdmin)
