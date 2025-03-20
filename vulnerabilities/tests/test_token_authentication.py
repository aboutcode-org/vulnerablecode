from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework import exceptions

from vulnerabilities.models import ExpiringToken
from vulnerabilities.token_authentication import ExpiringTokenAuthentication

User = get_user_model()


@pytest.mark.django_db
def test_expiring_token_creation():
    """
    Test tha ExpiringToken is created with an expiration date
    """
    user = User.objects.create_user(username="testuser", email="test@example.com")
    token, created = ExpiringToken.get_or_create(user=user)

    #token and its expiration date 30days from today
    #print(f"Token: {token.key}, Expires: {token.expires}")

    assert created is True
    assert token.expires > timezone.now()


@pytest.mark.django_db
def test_expiring_token_is_expired():
    """
    Test that is_expired method
    """
    user = User.objects.create_user(username="testuser", email="test@example.com")
    token = ExpiringToken.objects.create(user=user, expires=timezone.now() - timedelta(days=1))
    # token and its expiration date,yesterday
    # print(f"Token: {token.key}, Expires: {token.expires}")

    assert token.is_expired() is True #expired


@pytest.mark.django_db
def test_expiring_token_is_not_expired():
    """
    Test the is_expired method for a non-expired token
    """
    user = User.objects.create_user(username="testuser", email="test@example.com")
    token = ExpiringToken.objects.create(user=user, expires=timezone.now() + timedelta(days=1))

    #token and its expiration date,tomorrow
    # print(f"Token: {token.key}, Expires: {token.expires}")

    assert token.is_expired() is False #not expired


@pytest.mark.django_db
def test_expiring_token_authentication_valid():
    """
    Test that a valid token authenticates the user
    """
    user = User.objects.create_user(username="testuser", email="test@example.com")
    token = ExpiringToken.objects.create(user=user, expires=timezone.now() + timedelta(days=1))

    auth = ExpiringTokenAuthentication()
    authenticated_user, authenticated_token = auth.authenticate_credentials(token.key)

    # print(f'Authenticated User:{authenticated_user} and Authenticated Token:{authenticated_token}')

    assert authenticated_user == user
    assert authenticated_token == token


@pytest.mark.django_db
def test_expiring_token_authentication_expired():
    """
    Test that an expired token raises an AuthenticationFailed error
    """
    user = User.objects.create_user(username="testuser", email="test@example.com")
    token = ExpiringToken.objects.create(user=user, expires=timezone.now() - timedelta(days=1))

    auth = ExpiringTokenAuthentication()

    with pytest.raises(exceptions.AuthenticationFailed):
        auth.authenticate_credentials(token.key)


@pytest.mark.django_db
def test_expiring_token_authentication_invalid():
    """
    Test that an invalid/non-existin token raises an AuthenticationFailed error
    """
    auth = ExpiringTokenAuthentication()

    with pytest.raises(exceptions.AuthenticationFailed):
        auth.authenticate_credentials("invalid-token")
