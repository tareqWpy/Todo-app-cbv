from django.urls import include, path

app_name = "weather"
"""
urls related to the weather app.
"""
urlpatterns = [
    path("", include("weather.api.v1.urls")),
]
