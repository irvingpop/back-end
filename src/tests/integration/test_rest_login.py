import pytest
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.test import APIClient

from tests.test_data import DEFAULT_PASSWORD


def test_valid_rest_login(client: APIClient, user: User):
    res = client.post(
        reverse("rest_login"), {"email": user.email, "password": DEFAULT_PASSWORD}
    )

    assert res.status_code == 200
    assert res.data["key"] is not None

    # With TokenAuthentication, we only get the token key, not user details
    # The key is used for subsequent authenticated requests


# Commented out until email confirmation is required again
#
# @pytest.mark.django_db
# def test_unverified_email_rest_login(client: test.Client, user: User):
#     EmailAddress.objects.filter(email=user.email).update(verified=False)
#
#     res = client.post(
#         reverse("rest_login"), {"email": user.email, "password": user.username}
#     )
#
#     assert res.status_code == 400
#     assert "Email has not been verified" in res.data["error"]


def test_invalid_pass_rest_login(client: APIClient, user: User):
    res = client.post(
        reverse("rest_login"), {"email": user.email, "password": "wrongPass"}
    )

    assert res.status_code == 400
    assert res.data["error"] == "The email or password you entered is incorrect!"


def test_invalid_username_rest_login(client: APIClient, user: User):
    res = client.post(
        reverse("rest_login"), {"email": "wrong@email.com", "password": user.username}
    )

    assert res.status_code == 400
    assert res.data["error"] == "The email or password you entered is incorrect!"
