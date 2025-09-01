import datetime

from settings.components import config

AUTHENTICATION_BACKENDS = (
    # Needed to login by username in Django admin, regardless of `allauth`
    "django.contrib.auth.backends.ModelBackend",
    # `allauth` specific authentication methods, such as login by e-mail
    "allauth.account.auth_backends.AuthenticationBackend",
)

MIDDLEWARE = [
    # Corsheaders:
    "corsheaders.middleware.CorsMiddleware",
    # Django:
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.BCryptPasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.Argon2PasswordHasher",
]

# Password validation
# https://docs.djangoproject.com/en/2.1/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"
    },
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Django-Rest-Auth
# https://dj-rest-auth.readthedocs.io/en/latest/
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_AUTHENTICATION_METHOD = "email"

REST_AUTH = {
    # Enable JWT authentication
    "USE_JWT": True,
    "LOGIN_SERIALIZER": "core.serializers.LoginSerializer",
    "USER_DETAILS_SERIALIZER": "core.serializers.UserDetailsSerializer",
    "PASSWORD_RESET_CONFIRM_SERIALIZER": "core.serializers.PasswordResetConfirmSerializer",
    "REGISTER_SERIALIZER": "core.serializers.RegisterSerializer",
    # Configure dj-rest-auth to handle password resets completely
    "PASSWORD_RESET_SERIALIZER": "core.serializers.CustomPasswordResetSerializer",
    "PASSWORD_RESET_CONFIRM_SERIALIZER": "core.serializers.PasswordResetConfirmSerializer",
    # Use dj-rest-auth's URL generation instead of Django's built-in
    "PASSWORD_RESET_USE_SITES_DOMAIN": False,
    # Configure URL generation to use dj-rest-auth's own URLs
    "PASSWORD_RESET_CONFIRM_URL": "rest_password_reset_confirm",
    # Use our custom URL generator
    "PASSWORD_RESET_URL_GENERATOR": "core.handlers.custom_password_reset_url_generator",
    # Use our custom password reset form
    "PASSWORD_RESET_FORM": "core.forms.CustomPasswordResetForm",
    # JWT settings - None means no cookie auth, tokens are returned in response
    "JWT_AUTH_COOKIE": None,
    "JWT_AUTH_REFRESH_COOKIE": None,
    "JWT_AUTH_HTTPONLY": False,
    # Return JWT key as "key" for backward compatibility with frontend
    "JWT_SERIALIZER": "core.serializers.JWTSerializer",
}

# Simple JWT Configuration
from datetime import timedelta

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": False,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": config("SECRET_KEY", default=""),
    "VERIFYING_KEY": None,
    "AUDIENCE": None,
    "ISSUER": None,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
    "JTI_CLAIM": "jti",
}

# Allauth social providers
# https://django-allauth.readthedocs.io/en/latest/providers.html
SOCIALACCOUNT_PROVIDERS = {
    "google": {"SCOPE": ["profile", "email"], "AUTH_PARAMS": {"access_type": "online"}}
}

GITHUB_AUTH_CALLBACK_URL = config(
    "GITHUB_AUTH_CALLBACK_URL", default="http://localhost:3000/"
)

RECAPTCHA_PUBLIC_KEY = config("RECAPTCHA_PUBLIC_KEY", "MyRecaptchaKey123")
RECAPTCHA_PRIVATE_KEY = config("RECAPTCHA_PRIVATE_KEY", "MyRecaptchaPrivateKey456")

CORS_ORIGIN_ALLOW_ALL = True
