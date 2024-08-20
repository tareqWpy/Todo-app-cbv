from rest_framework import serializers
from todo.models import Task
from accounts.models import User


class TaskSerializers(serializers.ModelSerializer):
    """
    Serializer for Task model.

    This serializer is used to convert Task model instances into a format that can be easily
    serialized and sent over the network. It also handles deserialization of data received from
    the network into Task model instances.

    Attributes:
    - relative_url: A URLField that represents the relative URL of the task.
    - absolute_url: A SerializerMethodField that represents the absolute URL of the task.

    Meta:
    - model: The model class that this serializer is associated with (Task).
    - fields: The list of fields that should be included in the serialized representation.
    - read_only_fields: The list of fields that should be read-only in the serialized representation.
    """

    relative_url = serializers.URLField(source="get_absolute_api_url", read_only=True)
    absolute_url = serializers.SerializerMethodField()

    class Meta:
        model = Task
        fields = [
            "id",
            "user",
            "title",
            "complete",
            "relative_url",
            "absolute_url",
            "created_date",
            "updated_date",
        ]
        read_only_fields = ["user"]

    def get_absolute_url(self, obj):
        """
        Returns the absolute URL of the task.

        Args:
        - obj: The Task model instance for which the absolute URL needs to be generated.

        Returns:
        - The absolute URL of the task.
        """
        request = self.context.get("request")
        return request.build_absolute_uri(obj.pk)

    def to_representation(self, obj):
        """
        Customizes the serialized representation of the task.

        Args:
        - obj: The Task model instance to be serialized.

        Returns:
        - The serialized representation of the task, with certain fields removed based on the context.
        """
        request = self.context.get("request")
        rep = super().to_representation(obj)
        if request.parser_context.get("kwargs").get("pk"):
            rep.pop("relative_url", None)
            rep.pop("absolute_url", None)
        else:
            rep.pop("updated_date", None)

        return rep

    def create(self, validated_data):
        """
        Creates a new Task model instance using the validated data.

        Args:
        - validated_data: The validated data that will be used to create the new Task instance.

        Returns:
        - The newly created Task model instance.
        """
        validated_data["user"] = self.context["request"].user
        return super().create(validated_data)
