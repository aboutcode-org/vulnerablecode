from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication

from .models import ExpiringToken


class ExpiringTokenAuthentication(TokenAuthentication):
    model = ExpiringToken

    def authenticate_credentials(self, key):
        try:
            #try to fetch the token
            user, token = super().authenticate_credentials(key)
        except self.model.DoesNotExist:
            #if the token does not exist/invalid
            raise exceptions.AuthenticationFailed("Invalid token")

        if token.is_expired():
            #if the token has expired
            raise exceptions.AuthenticationFailed("Token has expired")
        return user, token
