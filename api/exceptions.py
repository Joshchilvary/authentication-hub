from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status


def custom_exception_handler(exc, context):
    """
    Custom exception handler that wraps DRF exceptions in the project's
    consistent JSON error format and prevents sensitive information leakage.
    """
    response = exception_handler(exc, context)

    if response is not None:
        error_data = {
            "success": False,
            "error": {
                "code": getattr(exc, "default_code", "error") or "error",
                "message": str(exc) if str(exc) else "An error occurred.",
            },
        }
        response.data = error_data

    return response
