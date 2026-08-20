from .base import *
from django.core.exceptions import ImproperlyConfigured

DEBUG = False

# ---------------------------------------------------------------------------
# Cloudinary media storage (production only)
# ---------------------------------------------------------------------------
# Production uses Cloudinary for persistent media storage.
# Local development continues to use local filesystem storage.
CLOUDINARY_STORAGE = {
    'CLOUD_NAME': os.environ.get('CLOUDINARY_CLOUD_NAME', ''),
    'API_KEY': os.environ.get('CLOUDINARY_API_KEY', ''),
    'API_SECRET': os.environ.get('CLOUDINARY_API_SECRET', ''),
}

STORAGES = {
    'default': {
        'BACKEND': 'cloudinary_storage.storage.MediaCloudinaryStorage',
    },
    'staticfiles': {
        'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage',
    },
}

# ---------------------------------------------------------------------------
# SECRET_KEY validation
# ---------------------------------------------------------------------------
# Production must not run with the insecure development fallback or an
# empty key. Raise a clear error at startup if the configuration is
# unsafe so the site fails closed rather than open.
_INSECURE_FALLBACK = "django-insecure-dev-key-change-in-production"

if not SECRET_KEY or SECRET_KEY == _INSECURE_FALLBACK:
    raise ImproperlyConfigured(
        "The SECRET_KEY environment variable must be set to a secure, "
        "non-empty value in production. Do not use the development fallback."
    )

# ---------------------------------------------------------------------------
# ALLOWED_HOSTS validation
# ---------------------------------------------------------------------------
if not ALLOWED_HOSTS:
    raise ImproperlyConfigured(
        "ALLOWED_HOSTS must be configured in production. "
        "Set it via the ALLOWED_HOSTS environment variable."
    )

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
# HSTS preload is intentionally disabled until a permanent custom domain
# is established. Preload requires domain ownership verification and
# browser-list submission, and Render-provided hostnames are not eligible.
SECURE_HSTS_PRELOAD = False

# Prevent browsers from guessing content types and from framing the site.
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'no-referrer-when-downgrade'

# Ensure cookies are HTTP-only to reduce XSS risk.
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

# Lax SameSite policy balances CSRF protection with usability.
SESSION_COOKIE_SAMESITE = "Lax"

# ---------------------------------------------------------------------------
# Reverse-proxy / HTTPS detection
# ---------------------------------------------------------------------------
# If this site is deployed behind a trusted reverse proxy (for example
# nginx, Cloudflare, or a platform load balancer) that sets the
# X-Forwarded-Proto header, set SECURE_PROXY_SSL_HEADER so Django can
# correctly detect HTTPS requests. Only enable this when the proxy is
# trusted and the header cannot be spoofed by the client.
#
# Example: SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
#
# You can also configure this via the SECURE_PROXY_SSL_HEADER environment
# variable using the format: "HTTP_X_FORWARDED_PROTO,https"
#
# Additionally, configure TRUSTED_PROXY_IPS with the proxy IP addresses
# so that X-Forwarded-For headers are only trusted from known proxies.
