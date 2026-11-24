# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from flask import (
    Blueprint,
    current_app,
    jsonify,
    redirect,
    session,
    url_for,
)
from flask_login import current_user
from invenio_accounts.models import UserIdentity
from invenio_db import db
from invenio_i18n import gettext as _

from ..models import RemoteAccount
from ..remote_apps.base import RemoteApp
from ..utils import (
    create_csrf_disabled_registrationform,
    fill_form,
    get_safe_redirect_target,
    get_session_next_url,
    require_more_than_one_external_account,
    set_session_next_url,
)
from .common import (
    complete_registration,
    core_authorized_handler,
    link_only_requires_login,
)


def response_handler(url: str, payload: dict | None = None):
    scheme, netloc, path, query, fragment = urlsplit(url)
    qs = parse_qs(query)
    if payload:
        for k, v in payload.items():
            qs[k] = [str(v)]

    return redirect(
        urlunsplit((scheme, netloc, path, urlencode(qs, doseq=True), fragment))
    )


rest_blueprint = Blueprint("invenio_oauthclient_rest", __name__, url_prefix="/oauth")


@rest_blueprint.route("/login/<remote_app:remote_app>")
@link_only_requires_login
def login(remote_app: RemoteApp):
    """Start the authentication workflow with the given remote app."""
    next_param = get_safe_redirect_target(arg="next")
    set_session_next_url(remote_app, next_param)

    redirect_url = url_for(".oauth_authorize", remote_app=remote_app, _external=True)
    return remote_app.client.authorize_redirect(redirect_url)


@rest_blueprint.route("/authorized/<remote_app:remote_app>/")  # for back-compat
@rest_blueprint.route("/authorized/<remote_app:remote_app>")
@link_only_requires_login
def oauth_authorize(remote_app: RemoteApp):
    # Note: Authlib takes care of ID token validation (aud, iss, etc.)
    if (to_url := core_authorized_handler(remote_app)) is not None:
        return redirect(to_url)

    return response_handler(
        "/",  # TODO
        payload={
            "message": _("Successfully authorized."),
            "code": 200,
            "next_url": get_session_next_url(remote_app),
        },
    )


@rest_blueprint.route("/signup/<remote_app:remote_app>", methods=["GET", "POST"])
def register(remote_app: RemoteApp):
    # TODO a KeyError here should redirect to the login, i suppose
    user_info = session[f"{remote_app.name}_userinfo"]
    token = session[f"{remote_app.name}_token"]
    form = create_csrf_disabled_registrationform(remote_app)
    fill_form(form, user_info.user)

    if not form.is_submitted():
        return response_handler(
            "/",  # TODO
            payload={
                "form": form.to_dict(),
                "remote": remote_app.name,
                "app_title": remote_app.title,
                "app_description": remote_app.description,
                "app_icon": remote_app.icon,
            },
        )

    elif not form.validate_on_submit():
        return jsonify({"message": _("Form validation error."), "code": 400}), 400

    complete_registration(remote_app, form, user_info, token)
    return (
        jsonify(
            {
                "message": _("Successfully signed up."),
                "code": 200,
                "next_url": get_session_next_url(remote_app),
            },
        ),
        200,
    )


@rest_blueprint.route("/disconnect/<remote_app:remote_app>")
@require_more_than_one_external_account
def disconnect(remote_app: RemoteApp):
    if not current_user.is_authenticated:
        url = current_app.config.get("OAUTHCLIENT_REST_DEFAULT_ERROR_REDIRECT_URL", "/")
        return response_handler(
            url, payload={"message": _("Unauthorized."), "code": 401}
        )

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
    return response_handler(
        "/", payload={"message": _("Successfully disconnected"), "code": 200}  # TODO
    )
