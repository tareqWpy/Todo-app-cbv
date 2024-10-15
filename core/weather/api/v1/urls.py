from django.urls import path

# Import views from the local module
from . import views

app_name = "api-v1"
# Define the URL patterns for the application
urlpatterns = [
    path("<str:city>/", views.WeatherApiView.as_view(), name="weather-api"),
]
