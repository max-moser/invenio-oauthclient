# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

from dataclasses import dataclass

from authlib.integrations.flask_client import FlaskOAuth2App, OAuth
from flask import Blueprint, flash, redirect, url_for
from flask_security import login_user
from werkzeug.routing import BaseConverter, ValidationError

from .handlers.token import set_session_next_url
from .oauth import oauth_get_user, oauth_authenticate
from .proxies import current_oauthclient
from .utils import get_safe_redirect_target

bp = Blueprint("invenio_authlib_client", __name__)


def info_serializer_handler(remote, token_user_info, user_info=None):
    """Serialize the account info response object.

    :param remote: The remote application.
    :param token_user_info: The content of the authorization token response.
    :param user_info: The response of the `user info` endpoint.
    :returns: A dictionary with serialized user information.
    """
    # fill out the information required by
    # 'invenio-accounts' and 'invenio-userprofiles'.
    #
    # note: "external_id": `preferred_username` should also work,
    #       as it is seemingly not editable in Keycloak

    user_info = user_info or {}  # prevent errors when accessing None.get(...)

    email = token_user_info.get("email") or user_info["email"]
    full_name = token_user_info.get("name") or user_info.get("name")
    username = token_user_info.get("preferred_username") or user_info.get(
        "preferred_username"
    )

    return {
        "user": {
            "active": True,
            "email": email,
            "profile": {
                "full_name": full_name,
                "username": username,
            },
        },
        "external_id": token_user_info["sub"],
        "external_method": remote.name,
    }


@dataclass
class ServerMetadata:
    request_token_url: str
    request_token_params: dict
    access_token_url: str
    access_token_params: dict
    refresh_token_url: str
    refresh_token_params: dict
    authorize_url: str
    authorize_params: dict
    api_base_url: str
    client_kwargs: dict


class RemoteApp:
    def __init__(
        self,
        name: str,
        server_metadata: str | ServerMetadata,
        client_id: str,
        client_secret: str,
        scope: list[str] | str,
        hidden: bool = False,
        link_only: bool = False,
    ):
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope if isinstance(scope, str) else " ".join(scope)
        self.hidden = hidden
        self.link_only = link_only

        self.server_metadata_url = None
        self.server_metadata = None
        self.client = None
        self.registration_form = None

        if isinstance(server_metadata, str):
            self.server_metadata_url = server_metadata
        else:
            self.server_metadata = server_metadata

    def register(self, oauth: OAuth) -> FlaskOAuth2App:
        # TODO use server_metadata if not server_metadata_url
        self.client = oauth.register(
            self.name,
            overwrite=False,
            server_metadata_url=self.server_metadata_url,
            client_id=self.client_id,
            client_secret=self.client_secret,
            client_kwargs={
                "scope": self.scope,
            },
        )
        return self.client

    def parse_user_info(self, user_info: dict) -> dict: ...


class KeycloakRemoteApp(RemoteApp):
    def parse_user_info(self, user_info: dict) -> dict:
        user_info = info_serializer_handler(self, user_info, user_info)
        return user_info


class RemoteAppConverter(BaseConverter):
    """Endpoint converter validating that the remote app is known."""

    def to_python(self, value: str) -> RemoteApp:
        try:
            return current_oauthclient.clients[value]
        except KeyError:
            raise ValidationError(f"{value} is not a known remote app")

    def to_url(self, value: RemoteApp | str) -> str:
        if isinstance(value, RemoteApp):
            return value.name
        return value


@bp.route("/login/<remote_app:remote_app>")
def login(remote_app: RemoteApp):
    """Start the authentication workflow with the given remote app."""
    next_param = get_safe_redirect_target(arg="next")
    set_session_next_url(remote_app.name, next_param)

    redirect_url = url_for(".oauth_authorize", remote_app=remote_app, _external=True)
    return remote_app.client.authorize_redirect(redirect_url)


@bp.route("/oauth/authorized/<remote_app:remote_app>")
def oauth_authorize(remote_app: RemoteApp):
    # Note: Authlib takes care of ID token validation (aud, iss, etc.)
    token = remote_app.client.authorize_access_token()

    # The initial ID token may hold very limited information, so we fetch more
    # user info from the endpoint and perform a quick sanity check
    remote_user_info = remote_app.client.userinfo()
    assert remote_user_info["sub"] == token["userinfo"]["sub"]
    user_info = remote_app.parse_user_info({**token["userinfo"], **remote_user_info})

    if user := oauth_get_user(remote_app.name, user_info, token):
        oauth_authenticate(remote_app.name, user)
    else:
        flash(f"User not found for user info: {user_info}")

    # TODO next url
    return redirect("/")


@bp.route("/signup/<remote_app:remote_app>", methods=["GET", "POST"])
def register(remote_app: RemoteApp):
    # TODO pull token & pre-filled form from session
    remote_app.registration_form



def fetch_token(name, request):
    # TODO check what this does again
    session_key = token_session_key(name)

    if session_key not in session and current_user.is_authenticated:
        # Fetch key from token store if user is authenticated, and the key
        # isn't already cached in the session.
        remote_token = RemoteToken.get(
            current_user.get_id(),
            remote.consumer_key,
            token_type=token,
        )

        if remote_token is None:
            return None

        # Store token and secret in session
        session[session_key] = remote_token.token()

    values = session.get(session_key, None)

    if values:
        access_token, secret, refresh_token, expires_str = values
        expires = datetime.fromisoformat(values[3])
        return access_token, secret, refresh_token, expires
    return values
