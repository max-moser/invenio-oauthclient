# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

from __future__ import annotations

from collections import UserDict

from authlib.integrations.base_client import OAuthError as AuthlibOAuthError
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_user
from invenio_accounts.models import UserIdentity
from invenio_accounts.views import login as base_login
from invenio_db import db
from joserfc.errors import JoseError
from requests import HTTPError

from ..models import RemoteAccount
from ..proxies import current_oauthclient
from ..errors import OAuthError
from ..remote import RemoteApp
from ..utils import (
    create_csrf_disabled_registrationform,
    _render_signup_form,
    create_registrationform,
    fill_form,
    get_safe_redirect_target,
    get_session_next_url,
    oauth_authenticate,
    oauth_get_user,
    oauth_register,
    parse_expires_at,
    require_more_than_one_external_account,
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


blueprint = Blueprint("invenio_authlib_client", __name__, url_prefix="/oauth")


@blueprint.route("/login/<remote_app:remote_app>")
def login(remote_app: RemoteApp):
    """Start the authentication workflow with the given remote app."""
    next_param = get_safe_redirect_target(arg="next")
    set_session_next_url(remote_app, next_param)

    redirect_url = url_for(".oauth_authorize", remote_app=remote_app, _external=True)
    return remote_app.client.authorize_redirect(redirect_url)


@blueprint.route("/authorized/<remote_app:remote_app>/")  # for back-compat
@blueprint.route("/authorized/<remote_app:remote_app>")
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

    access_token = token.get("access_token")
    remote_user_info = LazyDict(_get_user_info)
    token_user_info = remote_app.parse_user_info(
        token.get("userinfo", {}), remote_user_info, access_token
    )
    user_info = token_user_info.user

    # TODO check if access_token is supposed to be present
    if user := oauth_get_user(remote_app, token_user_info, access_token):
        if not oauth_authenticate(remote_app, user):
            # TODO handle login failure
            pass

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
            if not oauth_authenticate(remote_app, user):
                # TODO handle login failure
                pass

    # NOTE: the refresh token typically only gets supplied if "offline_access" is in the scope
    remote_app.finalize_login(
        user,
        token_user_info,
        access_token,
        refresh_token=token.get("refresh_token"),
        expires_at=parse_expires_at(token.get("expires_at")),
    )
    session["OAUTHCLIENT_SESSION_REMOTE_NAME"] = remote_app.name
    db.session.commit()
    return redirect(get_session_next_url(remote_app))


@blueprint.route("/signup/<remote_app:remote_app>", methods=["GET", "POST"])
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
            # NOTE: the refresh token typically only gets supplied if "offline_access" is in the scope
            remote_app.finalize_login(
                user,
                user_info,
                token["access_token"],
                refresh_token=token.get("refresh_token"),
                expires_at=parse_expires_at(token.get("expires_at")),
            )
            db.session.commit()
            return redirect(get_session_next_url(remote_app))

    # TODO provide REST endpoint for this as well


@blueprint.route("/disconnect/<remote_app:remote_app>")
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


@blueprint.route("/logout")
def post_logout():
    """Client logout view.

    This URL should be called by setting `SECURITY_POST_LOGOUT_VIEW = /oauth/logout`
    """
    remote_name = session.pop("OAUTHCLIENT_SESSION_REMOTE_NAME", None)
    clients = current_oauthclient.clients
    if remote_name and (logout_url := clients[remote_name].logout_url):
        return redirect(logout_url, code=302)

    return redirect("/")


@blueprint.route("/login")
def auto_redirect_login(*args, **kwargs):
    """Handles automatic redirect to external auth service.

    The login endpoint will redirect automatically to the external
    auth service if the following conditions are met:

    * local login is disabled
    * redirect to external login is enabled
    * only one external auth service is configured

    This function should be set as value of the invenio-accounts
    config var ``ACCOUNTS_LOGIN_VIEW_FUNCTION``. It should be defined in
    the Invenio application configuration to ensure that is correctly loaded.
    """
    local_login_enabled = current_app.config.get("ACCOUNTS_LOCAL_LOGIN_ENABLED", False)
    auto_redirect_enabled = current_app.config.get(
        "OAUTHCLIENT_AUTO_REDIRECT_TO_EXTERNAL_LOGIN", False
    )
    would_redirect = auto_redirect_enabled and not local_login_enabled
    remote_apps = current_oauthclient.clients.values()
    visible_remote_apps = [
        app for app in remote_apps if not app.hidden and not app.link_only
    ]

    if would_redirect and len(visible_remote_apps) == 1:
        redirect_args = {
            # if local login is disabled and we only have one OAuth2 remote app
            # configured, we forward directly to that
            "remote_app": visible_remote_apps[0],
        }
        next_url = request.args.get("next")
        if next_url:
            redirect_args["next"] = next_url
        url = url_for("invenio_authlib_client.login", **redirect_args)
        return redirect(url)

    else:
        return base_login(*args, **kwargs)
