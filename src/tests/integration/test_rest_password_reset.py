import re
from typing import List

from django.contrib.auth.models import User
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import EmailMultiAlternatives
from django.urls import reverse
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_encode
from rest_framework.test import APIClient

from tests.test_data import fake

# Pattern to match Django's built-in password reset URL format: /reset/<uid>/<token>/
token_pattern = re.compile(r"/reset/(?P<uid>[^/]+)/(?P<token>[^/]+)/")


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
    token = PasswordResetTokenGenerator().make_token(user)
    uid = urlsafe_base64_encode(force_str(user.pk).encode())
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
    uid = urlsafe_base64_encode(force_str(user.pk).encode())
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
    token = PasswordResetTokenGenerator().make_token(user)
    uid = urlsafe_base64_encode(force_str(user.pk).encode())
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
    uid = urlsafe_base64_encode(force_str(user.pk).encode())

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
