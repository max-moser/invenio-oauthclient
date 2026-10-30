# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

"""Utility methods."""

from __future__ import annotations

from datetime import UTC, datetime
from functools import wraps

from flask import (
    abort,
    after_this_request,
    current_app,
    render_template,
    request,
    session,
)
from flask.sansio.app import App
from flask_login import current_user
from flask_principal import RoleNeed
from flask_security import login_user, logout_user
from flask_security.confirmable import confirm_user, requires_confirmation
from invenio_accounts.models import User, UserIdentity
from invenio_accounts.utils import register_user
from invenio_base.jws import TimedJSONWebSignatureSerializer
from invenio_db import db
from invenio_db.utils import rebuild_encrypted_properties
from uritools import uricompose, urisplit
from werkzeug.local import LocalProxy
from werkzeug.utils import import_string

from ..models import RemoteAccount, RemoteToken
from ..oauth import _commit, _datastore
from ..proxies import current_oauthclient
from .data import UserInfo
from .remote import RemoteApp

_security = LocalProxy(lambda: current_app.extensions["security"])


serializer = LocalProxy(
    lambda: TimedJSONWebSignatureSerializer(
        current_app.config["SECRET_KEY"],
        expires_in=current_app.config["OAUTHCLIENT_STATE_EXPIRES"],
    )
)


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


def parse_expires_at(timestamp: float | None) -> datetime | None:
    """Parse the UNIX timestamp into a datetime."""
    if timestamp is None:
        return None

    return datetime.fromtimestamp(timestamp, tz=UTC)


def format_expires_at(expires: datetime | None) -> int | None:
    """Convert a datetime to a UNIX timestamp for authlib."""
    if expires is None:
        return None
    return int(expires.timestamp())


def filter_user_info(user_info, precedence_mask):
    """Filter the user info dictionary according to the precedence mask.

    :param user_info: The user info dictionary.
    :param precedence_mask: The precedence mask to use.
    """
    # for each of the user info values, check if they are supposed
    # to take precedence over user input (as per precedence mask)
    for key, user_info_value in list(user_info.items()):
        precedence_value = precedence_mask.get(key, True)
        info_val_dict = isinstance(user_info_value, dict)
        prec_val_dict = isinstance(precedence_value, dict)

        if info_val_dict and prec_val_dict:
            # if both values in the mask and user_info are dicts,
            # investigate deeper
            filter_user_info(user_info_value, precedence_mask[key])

        elif prec_val_dict:
            # the precedence mask says it's a dict, but it is actually
            # a different value... remove this inconsistent user_info value
            user_info.pop(key, None)

        elif not precedence_value:
            user_info.pop(key, None)


def patch_dictionary(orig_dict, patch_dict):
    """Replace the fields mentioned in the patch, while leaving others as is.

    Note: The first argument's content will be changed during the process.

    :param orig_dict: A dictionary.
    :param patch_dict: The dictionary whose values should take precedence.
    """
    for key in patch_dict:
        val = patch_dict[key]
        orig_val = orig_dict.get(key)

        if isinstance(val, dict) and isinstance(orig_val, dict):
            patch_dictionary(orig_val, val)
        else:
            orig_dict[key] = val


def remove_csrf_tokens(user_data):
    """Remove CSRF tokens from the user data."""
    user_data.pop("csrf_token", None)
    for key, value in list(user_data.items()):
        if isinstance(value, dict):
            remove_csrf_tokens(value)


def remove_none_values(user_data):
    """Remove None values from the user data."""
    del_keys = []
    for key, value in list(user_data.items()):
        if isinstance(value, dict):
            remove_none_values(value)
            if value == {}:
                del_keys.append(key)
        if value is None:
            del_keys.append(key)
    for key in del_keys:
        del user_data[key]


def get_safe_redirect_target(arg="next"):
    """Get URL to redirect to and ensure that it is local.

    :param arg: URL argument.
    :returns: The redirect target or ``None``.
    """
    allowed_hosts = current_app.config.get("TRUSTED_HOSTS") or []
    for target in request.args.get(arg), request.referrer:
        if target:
            redirect_uri = urisplit(target)
            if redirect_uri.host in allowed_hosts:
                return target
            elif redirect_uri.path:
                return uricompose(
                    path=redirect_uri.getpath(),
                    query=redirect_uri.getquery(),
                    fragment=redirect_uri.getfragment(),
                )
    return None


def obj_or_import_string(value, default=None):
    """Import string or return object."""
    if isinstance(value, str):
        return import_string(value)
    elif value:
        return value
    return default


def load_or_import_from_config(key, app=None, default=None):
    """Load or import value from config."""
    app = app or current_app
    imp = app.config.get(key)
    return obj_or_import_string(imp, default=default)


def _create_registrationform(*args, **kwargs):
    """Default registration form after external auth success."""

    class RegistrationForm(_security.confirm_register_form):
        password = None
        recaptcha = None
        submit = None  # defined in the template

    return RegistrationForm(*args, **kwargs)


def create_registrationform(*args, **kwargs):
    """Make a registration form."""
    func = current_app.config["OAUTHCLIENT_SIGNUP_FORM"]
    return func(*args, **kwargs)


def create_csrf_disabled_registrationform(remote):
    """Create a registration form with CSRF disabled."""
    func = current_app.config["OAUTHCLIENT_SIGNUP_FORM"]
    return func(oauth_remote_app=remote, **_get_csrf_disabled_param())


def rebuild_access_tokens(old_key):
    """Rebuild the access token field when the SECRET_KEY is changed.

    Fixes users' login

    :param old_key: the old SECRET_KEY.
    """
    current_app.logger.info("rebuilding RemoteToken.access_token...")
    rebuild_encrypted_properties(old_key, RemoteToken, ["access_token"])


def _get_csrf_disabled_param():
    """Return the right param to disable CSRF depending on WTF-Form version.

    From Flask-WTF 0.14.0, `csrf_enabled` param has been deprecated in favor of
    `meta={csrf: True/False}`.
    """
    import flask_wtf
    from packaging.version import Version

    supports_meta = Version(flask_wtf.__version__) >= Version("0.14.0")
    return {"meta": {"csrf": False}} if supports_meta else {"csrf_enabled": False}


def load_user_role_needs(identity):
    """Add User/RoleNeed to the logged in user whenever identity is loaded."""
    if identity.id is None:
        # no user is logged in
        return

    needs = set()

    roles_ids = session.get("unmanaged_roles_ids", [])
    for role_id in roles_ids:
        needs.add(RoleNeed(role_id))

    identity.provides |= needs


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


def fetch_token(remote_app_name: str):
    # This fetches the token for the given remote app for the current user;
    # used when creating requests with the remote app client, e.g.
    # `current_oauthclient.clients[NAME].client.get("/path/to/resource")`
    # TODO test this, e.g. with GitHub
    # TODO the authlib examples don't cache the token
    remote_app = current_oauthclient.clients[remote_app_name]
    session_key = f"{remote_app.name}_remote_token"

    if session_key not in session and current_user.is_authenticated:
        remote_token = RemoteToken.get(
            current_user.get_id(),
            remote_app.client_id,
            token_type="",
        )
        if remote_token is None:
            return None

        token = {
            "access_token": remote_token.access_token,
            "token_type": remote_token.token_type,
            "refresh_token": remote_token.refresh_token,
            "expires_at": format_expires_at(remote_token.expires),
        }
        session[session_key] = token
        return token

    return session.get(session_key, None)


def refresh_token(remote_app_name: str, token, refresh_token=None, access_token=None):
    # TODO this needs to be tested!
    remote_app = current_oauthclient.clients[remote_app_name]
    if not current_user.is_authenticated:
        return

    stored_token = None
    if refresh_token:
        stored_token = (
            db.session.query(RemoteToken)
            .join(RemoteAccount)
            .filter(
                RemoteToken.refresh_token == refresh_token,
                RemoteAccount.user_id == current_user.id,
                RemoteAccount.client_id == remote_app.client_id,
            )
            .first()
        )
    elif access_token:
        stored_token = (
            db.session.query(RemoteToken)
            .join(RemoteAccount)
            .filter(
                RemoteToken.access_token == access_token,
                RemoteAccount.user_id == current_user.id,
                RemoteAccount.client_id == remote_app.client_id,
            )
            .first()
        )
    else:
        return

    if stored_token:
        stored_token.update_token(
            token["access_token"],
            "",
            token.get("refresh_token"),
            parse_expires_at(token.get("expires_at")),
        )
        db.session.commit()
