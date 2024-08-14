from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.views import LoginView
from django.views.generic.edit import FormView
from django.urls import reverse_lazy
from django.contrib.auth import login
from django.shortcuts import redirect
from accounts.forms import CustomUserCreationForm

# Create your views here.


class CustomLoginView(LoginView):
    """
    A class-based costum login view to logging in based on email and password.
    """

    template_name = "accounts/login.html"
    fields = "email", "password"
    redirect_authenticated_user = True

    def get_success_url(self):
        """
        A function to redirect user after logging in to the task-list page.
        """
        return reverse_lazy("task-list")


class RegisterPage(FormView):
    """
    A class-based view for registering new users using a custom user creation form.
    This ensures that authenticated users are redirected from the registration page.
    """

    template_name = "accounts/register.html"
    form_class = CustomUserCreationForm
    redirect_authenticated_user = True
    success_url = reverse_lazy("task-list")

    def form_valid(self, form):
        """
        Called when valid form data is submitted.
        Saves the user and logs them in upon successful registration.
        """
        user = form.save()
        if user is not None:
            login(self.request, user)
        return super(RegisterPage, self).form_valid(form)

    def get(self, *args, **kwargs):
        """
        Handles GET requests.
        Redirects authenticated users to the task list, preventing access to the registration page.
        """
        if self.request.user.is_authenticated:
            return redirect("task-list")
        return super(RegisterPage, self).get(*args, **kwargs)
