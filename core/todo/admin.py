from django.contrib import admin

from todo.models import Task

"""
Registeration for Admin panel to present data of Taks.
"""
admin.site.register(Task)
