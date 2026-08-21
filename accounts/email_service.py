"""
Brevo transactional email service.

Provides a reusable helper for sending application emails through the
Brevo HTTP API (https://api.brevo.com/v3/smtp/email).

Production reads configuration from environment variables:
  BREVO_API_KEY
  DEFAULT_FROM_EMAIL
  BREVO_API_TIMEOUT

Local development may continue using Django's console email backend
if BREVO_API_KEY is not configured.
"""

import json
import logging
import socket
import urllib.error
import urllib.request
from typing import Optional

from django.conf import settings

logger = logging.getLogger(__name__)

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"
BREVO_API_TIMEOUT = 10


def send_brevo_email(
    subject: str,
    recipient_email: str,
    recipient_name: str = "",
    html_content: str = "",
    plain_text_content: Optional[str] = None,
) -> bool:
    """
    Send an email via Brevo's transactional SMTP API.

    Args:
        subject: Email subject line.
        recipient_email: Destination email address.
        recipient_name: Optional recipient display name.
        html_content: HTML body content.
        plain_text_content: Optional plain-text body content.

    Returns:
        True if Brevo accepted the request, False otherwise.
    """
    api_key = getattr(settings, "BREVO_API_KEY", "") or ""
    if not api_key:
        logger.error("Brevo email not sent: BREVO_API_KEY is not configured")
        return False

    from_email = getattr(settings, "DEFAULT_FROM_EMAIL", "") or ""
    if not from_email:
        logger.error("Brevo email not sent: DEFAULT_FROM_EMAIL is not configured")
        return False

    timeout = int(getattr(settings, "BREVO_API_TIMEOUT", BREVO_API_TIMEOUT))

    payload = {
        "sender": {"email": from_email},
        "to": [{"email": recipient_email, "name": recipient_name or ""}],
        "subject": subject,
        "htmlContent": html_content,
    }

    if plain_text_content:
        payload["textContent"] = plain_text_content

    data = json.dumps(payload).encode("utf-8")

    request = urllib.request.Request(
        BREVO_API_URL,
        data=data,
        headers={
            "api-key": api_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status < 400
    except socket.timeout:
        logger.error("Brevo API request timed out after %s seconds", timeout)
        return False
    except urllib.error.HTTPError as exc:
        logger.error(
            "Brevo API HTTP error: status=%s reason=%s",
            exc.code,
            exc.reason,
        )
        return False
    except urllib.error.URLError as exc:
        logger.error("Brevo API connection error: %s", exc.reason)
        return False
    except Exception as exc:
        logger.error("Brevo API unexpected error: %s", exc)
        return False
