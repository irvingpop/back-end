import logging

from allauth.account.models import EmailConfirmation
from allauth.account.signals import email_confirmed, user_signed_up
from django.contrib.auth.models import User
from django.dispatch import receiver
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

from background_task import background
from core.models import Profile

logger = logging.getLogger(__name__)


def custom_password_reset_url_generator(request, user, temp_key):
    """
    Custom URL generator for password resets that uses dj-rest-auth's URL names
    """
    # Use dj-rest-auth's password reset confirm URL
    path = reverse(
        'rest_password_reset_confirm',
        args=[urlsafe_base64_encode(force_bytes(user.pk)), temp_key],
    )

    # Build absolute URL
    from django.contrib.sites.shortcuts import get_current_site
    current_site = get_current_site(request)
    protocol = 'https' if request.is_secure() else 'http'
    return f"{protocol}://{current_site.domain}{path}"


@receiver(user_signed_up)
def user_signed_up_receiver(sender, user, **kwargs):
    """
    When a user signs up, create a background task to invite them to Slack
    """
    from core.tasks import send_slack_invite_job

    send_slack_invite_job(user.email)
    logger.info(f"Created Slack invite task for user {user.id}")


@receiver(email_confirmed)
def email_confirmed_receiver(sender, email_address, **kwargs):
    """
    When a user confirms their email, create a background task to add them to the mailing list
    """
    from core.tasks import add_user_to_mailing_list

    user = email_address.user
    add_user_to_mailing_list(user.email)
    logger.info(f"Created mailing list task for user {user.id}")
