from django.contrib import admin
from todo.models import Task


class TaskAdmin(admin.ModelAdmin):
    """
    A class for presenting the data in Admin panel.
    """

    model = Task
    list_display = (
        "title",
        "user",
        "complete",
    )


"""
Registeration for Admin panel to present data of Taks.
"""
admin.site.register(Task, TaskAdmin)
