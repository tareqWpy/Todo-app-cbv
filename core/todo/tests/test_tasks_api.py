import pytest
from accounts.models import User
from django.urls import reverse
from rest_framework.test import APIClient


@pytest.fixture
def api_client():
    """
    Returns an instance of APIClient for testing API endpoints.
    """
    client = APIClient()
    return client


@pytest.fixture
def common_user():
    """
    Creates and returns a common user for testing API endpoints.
    """
    user = User.objects.create_user(
        email="admin@admin.com", password="9889TAAT@@", is_verified=True
    )
    return user


@pytest.mark.django_db
class TestPostAPI:
    """
    Test suite for POST API endpoints related to tasks.
    """

    def test_get_task_response_200_status(self, api_client, common_user):
        """
        Test GET request to task list endpoint returns 200 status code.
        """
        url = reverse("todo:api-v1:task-list")
        user = common_user
        api_client.force_authenticate(user=user)
        response = api_client.get(url)
        assert response.status_code == 200

    def test_task_create_response_401_status(self, api_client):
        """
        Test POST request to task list endpoint without authentication returns 401 status code.
        """
        url = reverse("todo:api-v1:task-list")
        data = {
            "title": "Test Task",
        }
        response = api_client.post(url, data)
        assert response.status_code == 401

    def test_task_create_response_201_status(self, api_client, common_user):
        """
        Test POST request to task list endpoint with authentication returns 201 status code.
        """
        url = reverse("todo:api-v1:task-list")
        data = {
            "title": "Test Task",
        }
        user = common_user
        api_client.force_authenticate(user=user)
        response = api_client.post(url, data)
        assert response.status_code == 201

    def test_task_create_response_400_status_missing_data(
        self, api_client, common_user
    ):
        """
        Test POST request to task list endpoint with missing data returns 400 status code.
        """
        url = reverse("todo:api-v1:task-list")
        data = {}
        user = common_user
        api_client.force_authenticate(user=user)
        response = api_client.post(url, data)
        assert response.status_code == 400

    def test_task_create_response_400_status_invalid_data(
        self, api_client, common_user
    ):
        """
        Test POST request to task list endpoint with invalid data returns 400 status code.
        """
        url = reverse("todo:api-v1:task-list")
        data = {
            "title": "A" * 256,
        }
        user = common_user
        api_client.force_authenticate(user=user)
        response = api_client.post(url, data)
        assert response.status_code == 400

    def test_task_create_response_201_status_duplicate_title(
        self, api_client, common_user
    ):
        """
        Test POST request to task list endpoint with duplicate title returns 201 status code.
        """
        url = reverse("todo:api-v1:task-list")
        data = {
            "title": "Test Task",
        }
        user = common_user
        api_client.force_authenticate(user=user)
        api_client.post(url, data)
        response = api_client.post(url, data)
        assert response.status_code == 201
