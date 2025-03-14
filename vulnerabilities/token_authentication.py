from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication

from .models import ExpiringToken


class ExpiringTokenAuthentication(TokenAuthentication):
    model = ExpiringToken

    def authenticate_credentials(self, key):
        try:
            # Try to fetch the token from the database
            user, token = super().authenticate_credentials(key)
        except self.model.DoesNotExist:
            # If the token does not exist, raise an AuthenticationFailed exception
            raise exceptions.AuthenticationFailed("Invalid token")

        if token.is_expired():
            # If the token has expired raise exception
            raise exceptions.AuthenticationFailed("Token has expired")
        return user, token
