import re
from typing import List

from django.contrib.auth.models import User
from django.core.mail import EmailMultiAlternatives
from django.urls import reverse
from rest_framework.test import APIClient

# Import allauth utilities when testing with allauth
from allauth.account.forms import default_token_generator
from allauth.account.utils import user_pk_to_url_str

from tests.test_data import fake

# Pattern to match our custom password reset URL format: /auth/password/reset/confirm/?uid=<uid>&token=<token>
token_pattern = re.compile(r"/auth/password/reset/confirm/\?uid=(?P<uid>[^&]+)&token=(?P<token>[^&]+)")


def test_password_reset_sends_email(
    client: APIClient, user: User, mailoutbox: List[EmailMultiAlternatives]
):
    res = client.post(reverse("rest_password_reset"), {"email": user.email})

    assert res.status_code == 200
    assert len(mailoutbox) == 1

    # Check if email body exists and contains the expected URL pattern
    email_body = mailoutbox[0].body
    assert email_body is not None, "Email body should not be None"

    match = token_pattern.search(email_body)
    assert match is not None, f"Email body should contain password reset URL. Body: {email_body[:200]}..."

    groups = match.groupdict()
    assert groups["uid"]
    assert groups["token"]


def test_password_reset_invalid_email(
    client: APIClient, user: User, mailoutbox: List[EmailMultiAlternatives]
):
    res = client.post(reverse("rest_password_reset"), {"email": "bad@email"})

    assert res.status_code == 400
    assert len(mailoutbox) == 0


def test_password_reset_confirm(client: APIClient, user: User):
    token = default_token_generator.make_token(user)
    uid = user_pk_to_url_str(user)
    password = fake.password()

    res = client.post(
        reverse("rest_password_reset_confirm"),
        {
            "uid": uid,
            "token": token,
            "new_password1": password,
            "new_password2": password,
        },
    )

    if res.status_code != 200:
        print(f"Response status: {res.status_code}")
        print(f"Response data: {res.data}")
        print(f"Response content: {res.content}")

    assert res.status_code == 200


def test_password_reset_confirm_bad_token(client: APIClient, user: User):
    uid = user_pk_to_url_str(user)
    password = fake.password()

    res = client.post(
        reverse("rest_password_reset_confirm"),
        {
            "uid": uid,
            "token": "badToken",
            "new_password1": password,
            "new_password2": password,
        },
    )

    assert res.status_code == 400
    error = res.data["error"]
    assert error == "Could not reset password.  Reset token expired or invalid."


def test_password_reset_login_with_new_password(client: APIClient, user: User):
    token = default_token_generator.make_token(user)
    uid = user_pk_to_url_str(user)
    password = fake.password()

    res = client.post(
        reverse("rest_password_reset_confirm"),
        {
            "uid": uid,
            "token": token,
            "new_password1": password,
            "new_password2": password,
        },
    )

    assert res.status_code == 200

    res = client.post(
        reverse("rest_login"), {"email": user.email, "password": password}
    )

    assert res.status_code == 200


def test_password_reset_common_password_error(client: APIClient, user: User):
    uid = user_pk_to_url_str(user)

    res = client.post(
        reverse("rest_password_reset_confirm"),
        {
            "uid": uid,
            "token": "badToken",
            "new_password1": "password",
            "new_password2": "password",
        },
    )

    assert res.status_code == 400
    error = res.data["error"]
    assert error == "Could not reset password.  Reset token expired or invalid."
