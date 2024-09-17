from django import forms

from .models import Task


class TaskUpdateForm(forms.ModelForm):
    """
    A Custom form to create Tasks.
    """

    title = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control rounded-4",
                "name": "title",
                "placeholder": "enter the title",
            }
        ),
        label="",
    )

    class Meta:
        model = Task
        fields = ("title",)
