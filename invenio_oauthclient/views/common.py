# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

from dataclasses import asdict
from functools import partial, wraps

from authlib.integrations.base_client import OAuthError as AuthlibOAuthError
from flask import (
    current_app,
    flash,
    redirect,
    session,
    url_for,
)
from flask_login import current_user
from invenio_db import db
from invenio_i18n import gettext as _
from joserfc.errors import JoseError

from ..data import LazyDict, UserInfo
from ..models import RemoteToken
from ..remote_apps.base import RemoteApp
from ..signals import (
    account_info_received,
    account_setup_committed,
    account_setup_received,
)
from ..tasks import create_or_update_roles_task
from ..utils import (
    create_csrf_disabled_registrationform,
    fill_form,
    oauth_authenticate,
    oauth_get_user,
    oauth_register,
    parse_expires_at,
)


def link_only_requires_login(func):
    """Decorator to only allow link-only flows for authenticated users."""

    @wraps(func)
    def inner(remote_app):
        if not current_user.is_authenticated and remote_app.link_only:
            msg = _(
                "You can only link %(title)s if you have already signed in through a different method.",
                title=remote_app.title,
            )
            flash(msg)
            return redirect(url_for(current_app.login_manager.login_view))
        else:
            return func(remote_app)

    return inner


def _handle_unmanaged_roles(
    remote_app: RemoteApp, user_info: UserInfo, access_token: str
):
    session["unmanaged_roles_ids"] = set()
    if groups := remote_app.get_groups(user_info=user_info, access_token=access_token):
        create_or_update_roles_task.delay([asdict(group) for group in groups])

        # Set the unmanaged roles in the user session, used in other modules.
        # Unmanaged user roles are not stored in the DB for privacy reasons:
        # sys admins should not know the external groups of a user.
        session["unmanaged_roles_ids"] = {group.id for group in groups}


def core_authorized_handler(remote_app: RemoteApp) -> str | None:
    # Note: Authlib takes care of ID token validation (aud, iss, etc.)
    try:
        token = remote_app.client.authorize_access_token()
    except (AuthlibOAuthError, JoseError) as e:
        current_app.logger.error(e)
        flash("Authentication failed.", category="error")
        return "/"

    access_token = token.get("access_token")
    extra_user_info = LazyDict(partial(remote_app.get_more_user_info, access_token))
    user_info = remote_app.parse_user_info(token.get("userinfo", {}), extra_user_info)

    # Send the "account info" signal as backwards-compatible as possible
    account_info_received.send(
        remote_app, response=token, account_info=asdict(user_info)
    )

    # TODO check if access_token is supposed to be present
    if remote_app.link_only:
        # With the decorator guard, we know that the user was authenticated
        user = current_user

    elif user := oauth_get_user(remote_app, user_info, access_token):
        if not oauth_authenticate(remote_app, user):
            # TODO handle login failure
            pass

    else:
        flash(f"User not found for user info: {user_info.user}")
        # Try to register the user with the information that we have
        form = create_csrf_disabled_registrationform(remote_app)
        fill_form(form, user_info.user)

        # TODO replace this ugly call, maybe per app?
        if (
            user := oauth_register(
                form,
                user_info.user,
                precedence_mask=remote_app.precedence_mask,
                signup_options=remote_app.signup_options,
            )
        ) is None:
            # If registration did not work, then the user has to fill out a form
            # (note that the target URL depends on UI/API blueprint)
            session[f"{remote_app.name}_userinfo"] = user_info
            session[f"{remote_app.name}_token"] = token
            return url_for(".register", remote_app=remote_app)
        else:
            if not oauth_authenticate(remote_app, user):
                # TODO handle login failure
                pass

    # NOTE: the refresh token typically only gets supplied if "offline_access" is in the scope
    is_first_login = RemoteToken.get(user.id, remote_app.client_id) is None
    remote_app.finalize_login(
        user,
        user_info,
        access_token,
        refresh_token=token.get("refresh_token"),
        expires_at=parse_expires_at(token.get("expires_at")),
    )
    _handle_unmanaged_roles(
        remote_app=remote_app, user_info=user_info, access_token=access_token
    )
    session["OAUTHCLIENT_SESSION_REMOTE_NAME"] = remote_app.name

    # Send the "account setup" signal as backwards-compatible as possible on first login
    remote_token = RemoteToken.get(user.id, remote_app.client_id)
    if is_first_login:
        account_setup_received.send(
            remote_app,
            token=remote_token,
            response=token,
            account_setup=user_info.extra_data,
        )

    db.session.commit()

    # Send the "account setup committed" signal as backwards-compatible as possible
    if is_first_login:
        account_setup_committed.send(remote_app, token=remote_token)

    return None
