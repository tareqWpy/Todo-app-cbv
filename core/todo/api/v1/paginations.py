from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class DefaultPagination(PageNumberPagination):
    """
    Custom pagination class for RESTful APIs. Inherits from PageNumberPagination.

    Attributes:
    page_size: The number of items to display per page. Default is 5.
    """

    page_size = 5

    def get_paginated_response(self, data):
        """
        Returns a paginated response with additional metadata.

        Parameters:
        data (list): The list of items to be included in the 'results' field of the response.

        Returns:
        Response: A DRF Response object containing the paginated data and additional metadata.
        """
        return Response(
            {
                "links": {
                    "next": self.get_next_link(),
                    "previous": self.get_previous_link(),
                },
                "total_objects": self.page.paginator.count,
                "total_pages": self.page.paginator.num_pages,
                "results": data,
            }
        )
