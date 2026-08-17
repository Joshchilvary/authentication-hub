from .base import *

DEBUG = False

# ---------------------------------------------------------------------------
# Production security hardening
# ---------------------------------------------------------------------------

# Enforce HTTPS across the entire site.
SECURE_SSL_REDIRECT = True

# Ensure session and CSRF cookies are only sent over HTTPS.
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# HSTS: tell browsers to only access the site over HTTPS for one year.
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Lax SameSite policy balances CSRF protection with usability.
SESSION_COOKIE_SAMESITE = "Lax"

# ---------------------------------------------------------------------------
# SECRET_KEY validation
# ---------------------------------------------------------------------------
# Production must not run with the insecure development fallback or an
# empty key. Raise a clear error at startup if the configuration is
# unsafe so the site fails closed rather than open.
from django.core.exceptions import ImproperlyConfigured

_INSECURE_FALLBACK = "django-insecure-dev-key-change-in-production"

if not SECRET_KEY or SECRET_KEY == _INSECURE_FALLBACK:
    raise ImproperlyConfigured(
        "The SECRET_KEY environment variable must be set to a secure, "
        "non-empty value in production. Do not use the development fallback."
    )

# ---------------------------------------------------------------------------
# Reverse-proxy / HTTPS detection
# ---------------------------------------------------------------------------
# If this site is deployed behind a trusted reverse proxy (for example
# nginx, Cloudflare, or a platform load balancer) that sets the
# X-Forwarded-Proto header, uncomment the line below so Django can
# correctly detect HTTPS requests. Only enable this when the proxy is
# trusted and the header cannot be spoofed by the client.
#
# SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
