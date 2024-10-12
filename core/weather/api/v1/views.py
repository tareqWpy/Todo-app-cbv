import requests
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


class WeatherApiView(APIView):
    permission_classes = [AllowAny]
    BASE_URL = "https://dragon.best/api/glax_weather.json"

    def get(self, request, city):
        """Fetch weather data for a specified city."""
        response = self._get_weather_data(city)

        if response.status_code == status.HTTP_200_OK:
            return Response({"details": response.json()}, status=status.HTTP_200_OK)
        return self._handle_error(response)

    def _get_weather_data(self, city):
        """Make a request to the weather API."""
        params = {"location": city, "units": "metric"}
        return requests.get(self.BASE_URL, params=params)

    def _handle_error(self, response):
        """Handle API errors and return a standardized response."""
        error_message = {
            "details": response.json().get("message", "An error occurred"),
            "status_code": response.status_code,
        }
        return Response(error_message, status=response.status_code)
