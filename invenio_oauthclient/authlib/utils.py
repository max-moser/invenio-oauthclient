# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

from __future__ import annotations

from functools import wraps

from flask import (
    abort,
    after_this_request,
    current_app,
    session,
)
from flask.sansio.app import App
from flask_login import current_user
from flask_security import login_user, logout_user
from flask_security.confirmable import confirm_user, requires_confirmation
from invenio_accounts.models import User, UserIdentity
from invenio_accounts.utils import register_user
from invenio_db import db

from ..models import RemoteAccount, RemoteToken
from ..oauth import _commit, _datastore
from ..proxies import current_oauthclient
from ..utils import (
    filter_user_info,
    patch_dictionary,
    remove_csrf_tokens,
    remove_none_values,
)
from .data import UserInfo
from .remote import RemoteApp


def oauth_authenticate(
    remote_app: RemoteApp,
    user: User,
    require_existing_link: bool = False,
    require_user_confirmation: bool = False,
):
    """Authenticate an oauth authorized callback.

    :param client_id: The client id.
    :param user: A user instance.
    :param require_existing_link: If ``True``, check if remote account exists.
        (Default: ``False``)
    :returns: ``True`` if the user is successfully authenticated.
    """
    # this is for backwards compatibility and tests
    if require_user_confirmation and requires_confirmation(user):
        return False

    # Authenticate via the access token (access token used to get user_id)
    after_this_request(_commit)
    if login_user(user):
        if require_existing_link:
            account = RemoteAccount.get(user.id, remote_app.client_id)
            if account is None:
                logout_user()
                return False
        return True


def oauth_get_user(
    remote_app: RemoteApp,
    user_info: UserInfo | None = None,
    access_token: str | None = None,
) -> User | None:
    """Retrieve user object for the given request.

    Uses either the access token or extracted account information to retrieve
    the user object.
    """
    if access_token:
        token = RemoteToken.get_by_token(remote_app.client_id, access_token)
        if token:
            return token.remote_account.user

    if user_info:
        user = UserIdentity.get_user(
            user_info.external_method,
            user_info.external_id,
        )
        if user:
            return user

        if email := user_info.user.get("email"):
            return db.session.query(User).filter_by(email=email).one_or_none()
    return None


def oauth_register(
    form,
    user_info: dict | None = None,
    precedence_mask: dict | None = None,
    signup_options: dict | None = None,
) -> User | None:
    """Register user if possible.

    :param form: A form instance.
    :param user_info: The user info dictionary.
    :param precedence_mask: The precedence mask to use.
    :param signup_options: Extra signup options dict.
    :returns: A :class:`invenio_accounts.models.User` instance.
    """
    signup_options = signup_options or {}

    if form.validate():
        form_data = form.data

        # let relevant information from the OAuth service's user info
        # have precedence over the values specified by the user
        if user_info:
            default_mask = {"email": True}
            # act on form data so the `profile` is updated correctly
            filter_user_info(user_info, precedence_mask or default_mask)
            patch_dictionary(form_data, user_info)

        # re-populate the form after applying the precedence mask and
        # convert the form data to user model's data
        data = fill_form(form, form_data).to_dict()
        # see https://github.com/inveniosoftware/invenio-oauthclient/issues/275
        remove_none_values(data)
        # remove the CSRF tokens to avoid unexpected keyword arguments
        remove_csrf_tokens(data)

        send_register_msg = signup_options.get("send_register_msg", True)
        user = register_user(send_register_msg=send_register_msg, **data)
        auto_confirm = signup_options.get("auto_confirm", False)
        if auto_confirm:
            confirm_user(user)
        _datastore.commit()
        return user


def token_session_key(remote_app: RemoteApp):
    """Generate a session key used to store the token for a remote app.

    :param remote_app: The remote application.
    :returns: The session key.
    """
    prefix = current_app.config["OAUTHCLIENT_SESSION_KEY_PREFIX"]
    return f"{prefix}_{remote_app.name}".lstrip("_")


def get_session_next_url(remote_app):
    """Return redirect url stored in session.

    :param remote_app: The remote application.
    :returns: The redirect URL.
    """
    return session.get(f"{token_session_key(remote_app)}_next_url")


def set_session_next_url(remote_app, url):
    """Store redirect url in session for security reasons.

    :param remote_app: The remote application.
    :param url: the redirect URL.
    """
    session[f"{token_session_key(remote_app)}_next_url"] = url


def fill_form(form, data):
    """Prefill form with data.

    :param form: The form to fill.
    :param data: The data to insert in the form.
    :returns: A pre-filled form.
    """
    for key, value in data.items():
        if hasattr(form, key):
            field = getattr(form, key)
            if isinstance(value, dict):
                fill_form(field, value)
            elif field is not None:
                field.data = value
    return form


def token_delete(remote_app: RemoteApp, token: str = ""):
    """Remove OAuth access tokens from session.

    :param remote: The remote application.
    :param token: Type of token to get. Data passed from ``oauth.request()``
        to identify which token to retrieve. (Default: ``''``)
    :returns: The token.
    """
    session_key = token_session_key(remote_app)
    return session.pop(session_key, None)


def oauth_logout_handler(sender_app: App, user: User | None = None):
    """Remove all access tokens and OAuth session data on logout.

    This includes:
    - OAuth tokens for all remote apps
    - Unmanaged roles (groups) from the session
    """
    for remote in current_oauthclient.clients.values():
        token_delete(remote)
        session.pop(f"{remote.name}_token", None)
        session.pop(f"{remote.name}_remote_token", None)
        session.pop(f"{remote.name}_userinfo", None)

    # Clear unmanaged roles (groups) from session
    # These are set during OAuth login when a groups handler is configured
    session.pop("unmanaged_roles_ids", None)

    db.session.commit()


def require_more_than_one_external_account(f):
    """Require that the user has more than one external account for login.

    If the user only has one linked external account and no means for logging
    in via local credentials, the decorated function won't be executed.
    This decorator is useful for disconnect handlers, to prevent users from
    disconnecting their last potential means of authentication.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        if current_user.is_anonymous:
            return f(*args, **kwargs)

        local_login_enabled = current_app.config.get(
            "ACCOUNTS_LOCAL_LOGIN_ENABLED", True
        )
        password_set = current_user.password is not None
        local_login_possible = local_login_enabled and password_set
        if local_login_possible:
            return f(*args, **kwargs)

        client_ids = {
            remote_app.client_id
            for remote_app in current_oauthclient.clients.values()
            if not remote_app.hidden
        }
        linked_accounts = RemoteAccount.query.filter(
            RemoteAccount.user_id == current_user.get_id(),
            RemoteAccount.client_id.in_(client_ids),
        ).all()

        # find out all of the linked external accounts for the user
        # that are currently configured and not hidden
        # linked_accounts = [acc for acc in accounts if acc.client_id in client_ids]

        # execute the function only if local login is possible, or
        # there's more than one linked external account
        if len(linked_accounts) > 1:
            return f(*args, **kwargs)
        else:
            abort(400)

    return decorated
