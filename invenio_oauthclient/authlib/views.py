# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

from __future__ import annotations

from collections import UserDict

from authlib.integrations.base_client import OAuthError as AuthlibOAuthError
from flask import Blueprint, current_app, flash, redirect, request, session, url_for
from flask_login import current_user, login_user
from invenio_accounts.models import UserIdentity
from invenio_db import db
from joserfc.errors import JoseError
from requests import HTTPError
from werkzeug.routing import BaseConverter, ValidationError

from ..handlers.utils import require_more_than_one_external_account
from ..models import RemoteAccount
from ..proxies import current_oauthclient
from ..utils import (
    create_csrf_disabled_registrationform,
    create_registrationform,
    fill_form,
    get_safe_redirect_target,
)
from .authlib import _render_signup_form
from .errors import OAuthError
from .remote import RemoteApp
from .utils import (
    get_session_next_url,
    oauth_authenticate,
    oauth_get_user,
    oauth_register,
    set_session_next_url,
)


class LazyDict(UserDict):
    def __init__(self, load_func):
        self._data = None
        self.load_func = load_func

    @property
    def data(self):
        if self._data is None:
            self._data = self.load_func()
        return self._data

    def __getitem__(self, key):
        return self.data[key]

    def get(self, key, default=None):
        return self.data.get(key, default)

    def __len__(self):
        return len(self.data)


bp = Blueprint("invenio_authlib_client", __name__)


@bp.route("/login/<remote_app:remote_app>")
def login(remote_app: RemoteApp):
    """Start the authentication workflow with the given remote app."""
    next_param = get_safe_redirect_target(arg="next")
    set_session_next_url(remote_app, next_param)

    redirect_url = url_for(".oauth_authorize", remote_app=remote_app, _external=True)
    return remote_app.client.authorize_redirect(redirect_url)


@bp.route("/oauth/authorized/<remote_app:remote_app>")
def oauth_authorize(remote_app: RemoteApp):
    # Note: Authlib takes care of ID token validation (aud, iss, etc.)
    try:
        token = remote_app.client.authorize_access_token()
    except (AuthlibOAuthError, JoseError) as e:
        current_app.logger.error(e)
        flash("Authentication failed.", category="error")
        return redirect("/")

    # The initial ID token may hold very limited information, so we fetch more
    # user info from the endpoint and perform a quick sanity check
    # (only when actually needed, with the local proxy)
    def _get_user_info():
        try:
            remote_user_info = remote_app.client.userinfo()
            if "userinfo" in token:
                assert remote_user_info["sub"] == token["userinfo"]["sub"]
            return dict(remote_user_info)
        except HTTPError as e:
            current_app.logger.error(e)
            return {}

    remote_user_info = LazyDict(_get_user_info)
    token_user_info = remote_app.parse_user_info(
        token.get("userinfo", {}), remote_user_info, token["access_token"]
    )
    user_info = token_user_info.user

    # TODO check if access_token is supposed to be present
    if user := oauth_get_user(remote_app, token_user_info, token.get("access_token")):
        oauth_authenticate(remote_app, user)

    else:
        flash(f"User not found for user info: {user_info}")
        # Try to register the user with the information that we have
        form = create_csrf_disabled_registrationform(remote_app)
        fill_form(form, user_info)

        # TODO replace this ugly call, maybe per app?
        if (user := oauth_register(form, user_info, signup_options={})) is None:
            # If registration did not work, then the user has to fill out a form
            session[f"{remote_app.name}_userinfo"] = token_user_info
            session[f"{remote_app.name}_token"] = token
            return redirect(url_for(".register", remote_app=remote_app))
        else:
            oauth_authenticate(remote_app, user)

    remote_app.finalize_login(user, token_user_info, token["access_token"])
    db.session.commit()
    return redirect(get_session_next_url(remote_app))


@bp.route("/signup/<remote_app:remote_app>", methods=["GET", "POST"])
def register(remote_app: RemoteApp):
    form = create_registrationform(request.form, oauth_remote_app=remote_app)

    # TODO a KeyError here should redirect to the login, i suppose
    # TODO server-side session to avoid leaking info
    user_info = session[f"{remote_app.name}_userinfo"]
    token = session[f"{remote_app.name}_token"]

    if not form.is_submitted():
        # GET request
        try:
            return _render_signup_form(remote_app, form, user_info.user)
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
            raise OAuthError("Could not create user")
        else:
            login_user(user)
            remote_app.finalize_login(user, user_info, token["access_token"])
            db.session.commit()
            return redirect(get_session_next_url(remote_app))

    # TODO provide REST endpoint for this as well


@bp.route("/disconnect/<remote_app:remote_app>")
@require_more_than_one_external_account
def disconnect(remote_app: RemoteApp):
    if not current_user.is_authenticated:
        return current_app.login_manager.unauthorized()

    account = RemoteAccount.get(
        user_id=current_user.get_id(),
        client_id=remote_app.client_id,
    )
    remote_app.handle_disconnect(account)

    if account:
        with db.session.begin_nested():
            account.delete()
            UserIdentity.delete_by_user(remote_app.name, account.user)

    db.session.commit()
    return redirect(url_for("invenio_oauthclient_settings.index"))


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
