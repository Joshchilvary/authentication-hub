from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response


class CustomPagination(PageNumberPagination):
    """
    Custom pagination that wraps DRF's standard paginated response
    in the project's consistent JSON structure.
    """
    page_size = 10

    def get_paginated_response(self, data):
        return Response({
            "success": True,
            "data": {
                "count": self.page.paginator.count,
                "next": self.get_next_link(),
                "previous": self.get_previous_link(),
                "results": data,
            },
        })
