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
# Use TokenAuthentication instead of JWT
REST_USE_JWT = False

REST_AUTH = {
    "LOGIN_SERIALIZER": "core.serializers.LoginSerializer",
    "USER_DETAILS_SERIALIZER": "core.serializers.UserDetailsSerializer",
    "PASSWORD_RESET_CONFIRM_SERIALIZER": "core.serializers.PasswordResetConfirmSerializer",
    "REGISTER_SERIALIZER": "core.serializers.RegisterSerializer",
    "TOKEN_MODEL": "rest_framework.authtoken.models.Token",
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
