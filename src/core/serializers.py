from django.contrib.auth import get_user_model
from dj_rest_auth.registration.serializers import (
    RegisterSerializer as BaseRegisterSerializer,
)
from dj_rest_auth.registration.serializers import (
    SocialAccountSerializer as BaseSocialAccountSerializer,
)
from dj_rest_auth.serializers import LoginSerializer as BaseLoginSerializer
from dj_rest_auth.serializers import (
    PasswordChangeSerializer as BasePasswordChangeSerializer,
    PasswordResetConfirmSerializer as BasePasswordResetConfirmSerializer,
    UserDetailsSerializer as BaseUserDetailsSerializer,
    JWTSerializer as BaseJWTSerializer,
)
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.contrib.sites.shortcuts import get_current_site

from core.models import Profile


# noinspection PyAbstractClass
class LoginSerializer(BaseLoginSerializer):
    """
    Extends the default LoginSerializer in order to return
    custom error messages
    """

    def validate(self, attrs):
        try:
            return super().validate(attrs)
        except serializers.ValidationError as ex:
            ex.detail = "The email or password you entered is incorrect!"
            raise ex


# noinspection PyAbstractClass
class PasswordResetConfirmSerializer(BasePasswordResetConfirmSerializer):
    """
    Extends the default PasswordResetConfirmSerializer in order to return
    custom error messages
    """

    def validate(self, attrs):
        try:
            return super().validate(attrs)
        except serializers.ValidationError as ex:
            if "new_password2" in ex.detail:
                ex.detail = ex.detail["new_password2"][0]
            else:
                ex.detail = "Could not reset password.  Reset token expired or invalid."
            raise ex


# noinspection PyAbstractClass
class CustomSocialLoginSerializer(BaseSocialAccountSerializer):
    """
    Extends default SocialLoginSerializer to add additional details to some
    failed login attempts
    """

    def validate(self, attrs):
        try:
            res = super().validate(attrs)
            return res
        except ValidationError as ex:
            if "User is already registered with this e-mail address." in ex.detail:
                ex.detail[0] = (
                    "User is already registered with this e-mail address. "
                    "Please login using the form above."
                )
            raise ex


# noinspection PyAbstractClass
class RegisterSerializer(BaseRegisterSerializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True)
    first_name = serializers.CharField(write_only=True)
    last_name = serializers.CharField(write_only=True)
    # legacy compat
    zip = serializers.CharField(write_only=True, required=False)
    zipcode = serializers.CharField(write_only=True, required=False)

    # Overrides the default required password fields
    password1 = None
    password2 = None

    def get_cleaned_data(self):
        return {
            "username": self.validated_data.get("email", ""),
            "email": self.validated_data.get("email", ""),
            # allauth uses password1 internally for creation
            "password1": self.validated_data.get("password", ""),
            "first_name": self.validated_data.get("first_name", ""),
            "last_name": self.validated_data.get("last_name", ""),
            "zipcode": self.validated_data.get("zipcode", ""),
        }

    def validate(self, data):
        return data


UserModel = get_user_model()


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = "__all__"


class UserDetailsSerializer(BaseUserDetailsSerializer):
    profile = ProfileSerializer()

    class Meta:
        model = UserModel
        fields = ("username", "email", "first_name", "last_name", "profile")
        read_only_fields = ("email",)

    def to_representation(self, instance: UserModel) -> dict:
        """Move fields from Profile to user representation."""
        representation = super().to_representation(instance)
        profile = representation.pop("profile")
        representation["zipcode"] = profile["zipcode"]
        representation["is_mentor"] = profile["is_mentor"]
        return representation


class UserSerializer(BaseUserDetailsSerializer):
    profile = ProfileSerializer()

    class Meta:
        model = UserModel
        fields = ("username", "email", "first_name", "last_name", "profile")
        read_only_fields = ("email",)

    def to_representation(self, instance: UserModel) -> dict:
        """Move fields from Profile to user representation."""
        representation = super().to_representation(instance)
        profile = representation.pop("profile")
        profile.pop("user")

        for key, val in profile.items():
            representation[key] = val

        return representation

class CustomPasswordResetSerializer(serializers.Serializer):
    """
    Custom password reset serializer that handles email sending without relying on problematic form URL generation
    """
    email = serializers.EmailField()

    def validate_email(self, value):
        User = get_user_model()
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user found with this email address.")
        return value

    def save(self):
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        from django.core.mail import send_mail
        from django.template.loader import render_to_string
        from django.utils.html import strip_tags

        User = get_user_model()
        request = self.context.get('request')
        email = self.validated_data['email']
        users = User.objects.filter(email=email)

        for user in users:
            # Generate token
            temp_key = default_token_generator.make_token(user)

            # Generate a simple URL that the frontend can use
            # The frontend will collect the new password and make the API call
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # Generate the URL using dj-rest-auth's expected format
            # This URL should point to the frontend password reset page
            from django.conf import settings

            # Get the frontend URL from settings or use the current site
            if hasattr(settings, 'FRONTEND_URL') and settings.FRONTEND_URL:
                base_url = settings.FRONTEND_URL
            else:
                protocol = 'https' if request.is_secure() else 'http'
                current_site = get_current_site(request)
                domain = current_site.domain if current_site.domain else 'localhost:3000'
                base_url = f"{protocol}://{domain}"

            # The frontend expects these as query parameters
            url = f"{base_url}/auth/password/reset/confirm/?uid={uid}&token={temp_key}"

            context = {
                "current_site": current_site,
                "site_name": current_site.name if current_site else "Operation Code",
                "domain": current_site.domain if current_site and current_site.domain else "localhost:3000",
                "protocol": 'https' if request.is_secure() else 'http',
                "user": user,
                "password_reset_url": url,
                "uid": uid,
                "token": temp_key,
                "key": temp_key,  # For backward compatibility
                "request": request,
            }

            # Send the email
            subject = "Password Reset Request"
            html_message = render_to_string('registration/password_reset_email.html', context)
            plain_message = strip_tags(html_message)

            send_mail(
                subject,
                plain_message,
                None,  # Use DEFAULT_FROM_EMAIL
                [email],
                html_message=html_message,
                fail_silently=False,
            )


class JWTSerializer(BaseJWTSerializer):
    """
    Custom JWT serializer that returns the access token as 'key'
    for backward compatibility with the frontend
    """
    def to_representation(self, instance):
        data = super().to_representation(instance)
        # Map 'access' or 'access_token' to 'key' for backward compatibility
        if 'access' in data:
            data['key'] = data.pop('access')
        elif 'access_token' in data:
            data['key'] = data.pop('access_token')
        # Keep refresh token as is
        return data
