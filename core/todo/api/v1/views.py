from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import viewsets
from rest_framework.filters import OrderingFilter, SearchFilter
from rest_framework.permissions import IsAuthenticated

from ...models import Task
from .paginations import DefaultPagination
from .serializers import TaskSerializers


class TaskModelViewSet(viewsets.ModelViewSet):
    """
    A ModelViewSet for managing tasks. It filters tasks based on the authenticated user and provides
    options to filter by 'user' and 'complete' fields.

    Attributes:
    permission_classes: List of permissions classes that the viewset requires. In this case, only authenticated users are allowed to access the endpoints.

    serializer_class: The serializer class used for serializing and deserializing task data.

    filter_backends: List of filter backends that the viewset uses. In this case, DjangoFilterBackend is used to filter tasks based on 'user' and 'complete' fields.

    filterset_fields: List of fields that can be used for filtering tasks. In this case, tasks can be filtered by 'user' and 'complete' fields.

    search_fields: List of fields that can be used for searching tasks. In this case, tasks can be searched by 'title' and 'user__email' fields.

    ordering_fields: List of fields that can be used for ordering tasks. In this case, tasks can be ordered by 'published_date' field.

    pagination_class: The pagination class used for paginating the task list.

    """

    permission_classes = [IsAuthenticated]
    serializer_class = TaskSerializers
    filter_backends = [DjangoFilterBackend, SearchFilter]
    filterset_fields = {"complete": ["exact"], "created_date": ["gte", "lte"]}
    search_fields = ["title", "user__email"]
    ordering_fields = ["published_date"]
    pagination_class = DefaultPagination

    def get_queryset(self):
        """
        Returns a queryset of tasks filtered by the authenticated user.

        Parameters:
        None

        Returns:
        A QuerySet of Task objects filtered by the authenticated user.
        """
        user = self.request.user
        return Task.objects.filter(user=user)
