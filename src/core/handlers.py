import logging

from allauth.account.models import EmailConfirmation
from allauth.account.signals import email_confirmed, user_signed_up
from django.contrib.auth.models import User
from django.dispatch import receiver

from core.tasks import (
    add_user_to_mailing_list,
    send_slack_invite_job,
    send_welcome_email,
)

logger = logging.getLogger(__name__)


@receiver(user_signed_up)
def registration_callback(user: User, **kwargs: dict) -> None:
    """
    Listens for the `user_signed_up` signal and adds a background tasks to
    send the welcome email and slack invite
    """
    logger.info(f"Received user_signed_up signal for {user}")
    print(f"DEBUG: user_signed_up signal triggered for {user.email}")
    send_slack_invite_job(user.email)
    send_welcome_email(user.email)


@receiver(email_confirmed)
def email_confirmed_callback(email_address: EmailConfirmation, **kwargs: dict) -> None:
    """
    Listens for the `email_confirmed` signal and adds a background task to
    add the user to the mailing list
    """
    logger.info(f"Received email_confirmed signal for {email_address.email}")
    print(f"DEBUG: email_confirmed signal triggered for {email_address.email}")
    add_user_to_mailing_list(email_address.email)
