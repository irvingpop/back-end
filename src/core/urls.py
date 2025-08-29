from django.urls import include, path
from django.views.generic import TemplateView
from dj_rest_auth.registration.views import SocialAccountListView, VerifyEmailView
from dj_rest_auth.views import PasswordChangeView, PasswordResetConfirmView

from . import views

urlpatterns = [
    path(
        "auth/password/change/",
        PasswordChangeView.as_view(),
        name="rest_password_change",
    ),
    path("auth/verify-email/", VerifyEmailView.as_view(), name="rest_verify_email"),
    path("auth/social/google/", views.GoogleLogin.as_view(), name="google_rest_login"),
    path(
        "auth/social/google/connect/",
        views.GoogleConnect.as_view(),
        name="google_connect",
    ),
    path("auth/social/facebook/", views.FacebookLogin.as_view(), name="fb_rest_login"),
    path(
        "auth/social/facebook/connect/",
        views.FacebookConnect.as_view(),
        name="facebook_connect",
    ),
    path("auth/social/github/", views.GithubLogin.as_view(), name="gh_rest_login"),
    path("auth/social/list/", SocialAccountListView.as_view(), name="social_list"),
    path("auth/registration/", views.RegisterView.as_view(), name="rest_register"),
    path("auth/profile/", views.UpdateProfile.as_view(), name="update_profile"),
    path("auth/me/", views.UpdateProfile.as_view(), name="update_my_profile"),
    path(
        "auth/profile/admin/",
        views.AdminUpdateProfile.as_view(),
        name="admin_update_profile",
    ),
    path("auth/user/", views.UserView.as_view(), name="view_user"),
    # Used by allauth to send the "verification email sent" response to client
    path(
        "auth/account-email-verification-sent",
        TemplateView.as_view(),
        name="account_email_verification_sent",
    ),
    path("auth/", include("dj_rest_auth.urls")),
    path("auth/accounts/", include("allauth.socialaccount.urls")),
    # Include Django's built-in password reset URLs for dj-rest-auth compatibility
    path("", include("django.contrib.auth.urls")),
]
