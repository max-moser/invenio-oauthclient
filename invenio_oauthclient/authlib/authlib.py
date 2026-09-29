# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT


from flask import (
    current_app,
    render_template,
    session,
)
from flask_security import current_user
from invenio_accounts.models import User, UserIdentity
from invenio_db import db

from ..models import RemoteAccount, RemoteToken
from .remote import RemoteApp
from .utils import fill_form


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

    access_token = token["access_token"]
    if remote_token := RemoteToken.get(user.id, remote_app.name):
        remote_token.update_token(token=access_token, secret="")
    else:
        RemoteToken.create(user.id, remote_app.name, token=access_token, secret="")
    db.session.commit()


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


def fetch_token(remote_app: RemoteApp):
    # This fetches the token for the given remote app for the current user;
    # used when creating requests with the remote app client, e.g.
    # `current_oauthclient.clients[NAME].client.get("/path/to/resource")`
    # TODO test this, e.g. with GitHub
    # TODO the authlib examples don't cache the token
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
            "expires_at": remote_token.expires,
        }
        session[session_key] = token
        return token

    return session.get(session_key, None)


def refresh_token(remote_app: RemoteApp, token, refresh_token=None, access_token=None):
    # TODO this needs to be tested!
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
                RemoteAccount.client_id == remote_app.name,
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
                RemoteAccount.client_id == remote_app.name,
            )
            .first()
        )
    else:
        return

    if stored_token:
        stored_token.update_token(
            token["access_token"], "", token["refresh_token"], token["expires_at"]
        )
        db.session.commit()
