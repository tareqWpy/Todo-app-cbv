from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated
from .serializers import TaskSerializers
from rest_framework import viewsets
from django_filters.rest_framework import DjangoFilterBackend
from ...models import Task


class TaskModelViewSet(viewsets.ModelViewSet):
    """
    A ModelViewSet for managing tasks. It filters tasks based on the authenticated user and provides
    options to filter by 'user' and 'complete' fields.
    """

    permission_classes = [IsAuthenticated]
    """
    List of permissions classes that the viewset requires. In this case, only authenticated users
    are allowed to access the endpoints.
    """

    serializer_class = TaskSerializers
    """
    The serializer class used for serializing and deserializing task data.
    """

    filter_backends = [DjangoFilterBackend]
    """
    List of filter backends that the viewset uses. In this case, DjangoFilterBackend is used to
    filter tasks based on 'user' and 'complete' fields.
    """

    filterset_fields = ["user", "complete"]
    """
    List of fields that can be used for filtering tasks. In this case, tasks can be filtered by 'user'
    and 'complete' fields.
    """

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
