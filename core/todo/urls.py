from django.urls import path, include
from .views import (
    TaskList,
    TaskCreate,
    TaskComplete,
    TaskUpdate,
    TaskDelete,
)

app_name = "todo"
"""
Important urls related to the todo app.
"""
urlpatterns = [
    path("", TaskList.as_view(), name="task-list"),
    path("create/", TaskCreate.as_view(), name="create-task"),
    path("update/<int:pk>/", TaskUpdate.as_view(), name="update-task"),
    path("complete/<int:pk>/", TaskComplete.as_view(), name="compelete-task"),
    path("delete/<int:pk>/", TaskDelete.as_view(), name="delete-task"),
    path("api/v1/", include("todo.api.v1.urls")),
]
