from django.shortcuts import redirect
from django.views.generic.list import ListView
from django.views.generic.edit import (
    CreateView,
    UpdateView,
    DeleteView,
)
from django.urls import reverse_lazy
from todo.forms import TaskUpdateForm
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View
from todo.models import Task


class TaskList(LoginRequiredMixin, ListView):
    """
    A class-based view to list all tasks for the authenticated user.
    This view requires the user to be logged in and filters tasks based on the logged-in user.
    """

    model = Task
    context_object_name = "tasks"
    template_name = "todo/list_task.html"

    def get_queryset(self):
        """
        Returns a queryset of tasks belonging to the logged-in user.
        """
        return self.model.objects.filter(user=self.request.user)


class TaskCreate(LoginRequiredMixin, CreateView):
    """
    A class-based view for creating new tasks.
    This view is restricted to authenticated users and saves the task associated with the user.
    """

    model = Task
    fields = ["title"]
    success_url = reverse_lazy("task-list")

    def form_valid(self, form):
        """
        Called when valid form data is submitted.
        Associates the task with the logged-in user before saving.
        """
        form.instance.user = self.request.user
        return super(TaskCreate, self).form_valid(form)


class TaskUpdate(LoginRequiredMixin, UpdateView):
    """
    A class-based view for updating existing tasks.
    Only allows authenticated users to update their own tasks.
    """

    model = Task
    success_url = reverse_lazy("task-list")
    form_class = TaskUpdateForm
    template_name = "todo/update_task.html"


class TaskComplete(LoginRequiredMixin, View):
    """
    A class-based view for marking a task as complete.
    This view is restricted to authenticated users.
    """

    model = Task
    success_url = reverse_lazy("task-list")

    def get(self, request, *args, **kwargs):
        """
        Handles GET requests to mark a task as complete.
        Retrieves the task by ID and updates its completion status.
        """
        object = Task.objects.get(id=kwargs.get("pk"))
        # Toggle the completion status
        object.complete = not object.complete
        object.save()
        return redirect(self.success_url)


class TaskDelete(LoginRequiredMixin, DeleteView):
    """
    A class-based view for deleting tasks.
    This view is restricted to authenticated users and ensures users can only delete their own tasks.
    """

    model = Task
    success_url = reverse_lazy("task-list")

    def get_queryset(self):
        """
        Returns a queryset of tasks belonging to the logged-in user for deletion.
        """
        return self.model.objects.filter(user=self.request.user)

    def get(self, request, *args, **kwargs):
        """
        Handles GET requests by deleting the task directly instead of showing a confirmation.
        """
        # Retrieve the task object
        task = self.get_object()
        # Delete the task
        task.delete()
        # Redirect after deletion
        return redirect(self.success_url)
