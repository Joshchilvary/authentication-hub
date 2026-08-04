from django.shortcuts import render


def home(request):
    """
    Render the public homepage.

    Shows different primary buttons based on whether the user is
    authenticated (Go to Dashboard) or not (Get Started / Register).
    Unauthenticated users also see a Login button.

    Args:
        request: The HTTP request object.

    Returns:
        HttpResponse: Rendered homepage template.
    """
    return render(request, "core/home.html")
