# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

from __future__ import annotations

from dataclasses import asdict

from authlib.integrations.base_client import MismatchingStateError
from flask import Blueprint, flash, redirect, request, session, url_for
from flask_login import login_user
from requests import HTTPError
from werkzeug.local import LocalProxy
from werkzeug.routing import BaseConverter, ValidationError

from ..proxies import current_oauthclient
from ..utils import (
    create_csrf_disabled_registrationform,
    create_registrationform,
    fill_form,
    get_safe_redirect_target,
)
from .authlib import _finalize_login, _render_signup_form
from .errors import OAuthError
from .remote import RemoteApp
from .utils import (
    get_session_next_url,
    oauth_authenticate,
    oauth_get_user,
    oauth_register,
    set_session_next_url,
)

bp = Blueprint("invenio_authlib_client", __name__)


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
    try:
        token = remote_app.client.authorize_access_token()
    except MismatchingStateError:
        # The state of the request and response are mismatched, e.g. when the user
        # refreshes on the authorize page
        flash("The login request was stale, please try again.")
        return redirect("/")

    # The initial ID token may hold very limited information, so we fetch more
    # user info from the endpoint and perform a quick sanity check
    # (only when actually needed, with the local proxy)
    def _get_user_info():
        try:
            remote_user_info = remote_app.client.userinfo()
            assert remote_user_info["sub"] == token["userinfo"]["sub"]
            return remote_user_info
        except HTTPError:
            return {}

    remote_user_info = LocalProxy(_get_user_info)

    token_user_info = remote_app.parse_user_info(token["userinfo"], remote_user_info)
    user_info = token_user_info.user

    # TODO check if access_token is supposed to be present
    if user := oauth_get_user(
        remote_app, asdict(token_user_info), token.get("access_token")
    ):
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

    _finalize_login(user, remote_app, token)
    return redirect(get_session_next_url(remote_app.name))


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
            raise OAuthError("Could not create user")
        else:
            login_user(user)
            _finalize_login(user, remote_app, session.get(f"{remote_app.name}_token"))
            return redirect(get_session_next_url(remote_app.name))

    # TODO provide REST endpoint for this as well


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
