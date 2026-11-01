"""Building your own forms by calling Cognito's API, instead of using managed login.

You get full control of the design. In exchange, your server now handles passwords, and you
lose features that managed login gives you for free.
"""

import base64
import hashlib
import hmac

import boto3
from botocore.exceptions import ClientError


class SignInFailed(Exception):
    pass


def secret_hash(username: str, client_id: str, client_secret: str) -> str:
    digest = hmac.new(
        client_secret.encode(), f"{username}{client_id}".encode(), hashlib.sha256
    ).digest()
    return base64.b64encode(digest).decode()


class CognitoUsers:
    def __init__(self, client_id: str, client_secret: str, region: str, client=None) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.client = client or boto3.client("cognito-idp", region_name=region)

    def _with_hash(self, username: str) -> dict:
        if not self.client_secret:
            return {}
        return {"SecretHash": secret_hash(username, self.client_id, self.client_secret)}

    def sign_up(self, email: str, password: str) -> None:
        try:
            self.client.sign_up(
                ClientId=self.client_id,
                Username=email,
                Password=password,
                UserAttributes=[{"Name": "email", "Value": email}],
                **self._with_hash(email),
            )
        except self.client.exceptions.UsernameExistsException:
            # Same outcome as success, so sign-up cannot reveal who has an account.
            return

    def confirm(self, email: str, code: str) -> None:
        self.client.confirm_sign_up(
            ClientId=self.client_id,
            Username=email,
            ConfirmationCode=code,
            **self._with_hash(email),
        )

    def sign_in(self, email: str, password: str) -> dict:
        parameters = {"USERNAME": email, "PASSWORD": password}
        if self.client_secret:
            parameters["SECRET_HASH"] = secret_hash(email, self.client_id, self.client_secret)
        try:
            response = self.client.initiate_auth(
                ClientId=self.client_id,
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters=parameters,
            )
        except ClientError as exc:
            # Wrong password and unknown user both end here, with one message.
            raise SignInFailed("Invalid email or password") from exc
        return response["AuthenticationResult"]
