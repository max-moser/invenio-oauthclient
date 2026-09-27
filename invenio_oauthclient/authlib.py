# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

from dataclasses import dataclass

from authlib.integrations.base_client.errors import MismatchingStateError
from authlib.integrations.flask_client import FlaskOAuth2App, OAuth
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_security import login_user
from invenio_accounts.models import User, UserIdentity
from invenio_db import db
from werkzeug.routing import BaseConverter, ValidationError

from .errors import OAuthClientUserNotRegistered
from .handlers.token import set_session_next_url
from .models import RemoteToken
from .oauth import oauth_authenticate, oauth_get_user, oauth_register
from .proxies import current_oauthclient
from .utils import (
    create_csrf_disabled_registrationform,
    create_registrationform,
    fill_form,
    get_safe_redirect_target,
)

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
            "username": (username or email.split("@")[0]).replace(".", "_"),
            "user_profile": {
                "full_name": full_name,
                "affiliations": "who the fuck knows",
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


def _finalize_login(user: User, remote_app: RemoteApp, token: dict):
    user_identity = (
        db.session.query(UserIdentity)
        .filter(UserIdentity.user == user, UserIdentity.method == remote_app.name)
        .one_or_none()
    )
    if user_identity:
        user_identity.id = token["userinfo"]["sub"]
    else:
        UserIdentity.create(user, remote_app.name, token["userinfo"]["sub"])

    # TODO should be access_token
    access_token = token["id_token"]
    if remote_token := RemoteToken.get(user.id, remote_app.name):
        remote_token.update_token(token=access_token, secret="")
    else:
        RemoteToken.create(user.id, remote_app.name, token=access_token, secret="")
    db.session.commit()


@bp.route("/oauth/authorized/<remote_app:remote_app>")
def oauth_authorize(remote_app: RemoteApp):
    from authlib.oidc.core.claims import IDToken

    # TODO this is just a hack to get the free OP working
    class MyIDToken(IDToken):
        ESSENTIAL_CLAIMS = [c for c in IDToken.ESSENTIAL_CLAIMS if c != "aud"]

        def validate_nonce(self):
            return

    # Note: Authlib takes care of ID token validation (aud, iss, etc.)
    try:
        token = remote_app.client.authorize_access_token(claims_cls=MyIDToken)
    except MismatchingStateError:
        # The state of the request and response are mismatched, e.g. when the user
        # refreshes on the authorize page
        flash("The login request was stale, please try again.")
        return redirect("/")

    # The initial ID token may hold very limited information, so we fetch more
    # user info from the endpoint and perform a quick sanity check
    # remote_user_info = remote_app.client.userinfo()
    remote_user_info = {}
    # assert remote_user_info["sub"] == token["userinfo"]["sub"]
    # TODO patch_dict for nested dicts
    token_user_info = remote_app.parse_user_info(
        {**token["userinfo"], **remote_user_info}
    )
    user_info = token_user_info["user"]

    # TODO check if access_token is supposed to be present
    if user := oauth_get_user(remote_app, token_user_info, token.get("access_token")):
        oauth_authenticate(remote_app.name, user)

    else:
        flash(f"User not found for user info: {user_info}")
        # Try to register the user with the information that we have
        form = create_csrf_disabled_registrationform(remote_app)
        fill_form(form, user_info)

        # TODO replace this ugly call, maybe per app?
        if (user := oauth_register(form, user_info, signup_options={})) is None:
            # If registration did not work, then the user has to fill out a form
            session[f"{remote_app.name}_userinfo"] = user_info
            session[f"{remote_app.name}_token"] = token
            return redirect(url_for(".register", remote_app=remote_app))

    # TODO next url
    # TODO store the token
    _finalize_login(user, remote_app, token)
    return redirect("/")


def _render_signup_form(remote_app: RemoteApp, form, account_info: dict):
    fill_form(form, account_info)
    return render_template(
        current_app.config["OAUTHCLIENT_SIGNUP_TEMPLATE"],
        form=form,
        # remote=remote,
        app_title=remote_app.name,
        app_description="description eh?",
        app_icon="no icon here",
    )


@bp.route("/signup/<remote_app:remote_app>", methods=["GET", "POST"])
def register(remote_app: RemoteApp):
    form = create_registrationform(request.form, oauth_remote_app=remote_app)
    if not form.is_submitted():
        # GET request
        try:
            user_info = session.pop(f"{remote_app.name}_userinfo")
            # token = session.pop(f"{remote_app.name}_token")
            return _render_signup_form(remote_app, form, user_info)
        except KeyError:
            flash("Could not find the user information from the login in the session.")
            return redirect("/")

    elif not form.validate_on_submit():
        # Form had errors
        flash("not valid: " + str(form.to_dict()))
        flash(str(request.form.to_dict()))
        return _render_signup_form(remote_app, form, {})

    else:
        # TODO replace this ugly call, maybe per app?
        if (user := oauth_register(form, {}, signup_options={})) is None:
            flash(form)
            # Form data valid, but impossible to create user
            raise Exception("Could not create user")
        else:
            login_user(user)
            _finalize_login(user, remote_app, session.get(f"{remote_app.name}_token"))
            return redirect("/")

    # TODO store the token
    # TODO provide REST endpoint for this as well


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
