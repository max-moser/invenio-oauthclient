# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT


from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    request,
    session,
    url_for,
)
from flask_login import current_user
from invenio_accounts.models import UserIdentity
from invenio_accounts.views import login as base_login
from invenio_db import db

from ..models import RemoteAccount
from ..proxies import current_oauthclient
from ..remote_apps.base import RemoteApp
from ..utils import (
    _render_signup_form,
    create_registrationform,
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

ui_blueprint = Blueprint("invenio_oauthclient", __name__, url_prefix="/oauth")


@ui_blueprint.route("/login/<remote_app:remote_app>")
@link_only_requires_login
def login(remote_app: RemoteApp):
    """Start the authentication workflow with the given remote app."""
    next_param = get_safe_redirect_target(arg="next")
    set_session_next_url(remote_app, next_param)

    redirect_url = url_for(".oauth_authorize", remote_app=remote_app, _external=True)
    return remote_app.client.authorize_redirect(redirect_url)


@ui_blueprint.route("/authorized/<remote_app:remote_app>/")  # for back-compat
@ui_blueprint.route("/authorized/<remote_app:remote_app>")
@link_only_requires_login
def oauth_authorize(remote_app: RemoteApp):
    if (to_url := core_authorized_handler(remote_app)) is not None:
        return redirect(to_url)

    return redirect(get_session_next_url(remote_app))


@ui_blueprint.route("/signup/<remote_app:remote_app>", methods=["GET", "POST"])
def register(remote_app: RemoteApp):
    form = create_registrationform(request.form, oauth_remote_app=remote_app)

    # TODO a KeyError here should redirect to the login, i suppose
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
        return _render_signup_form(remote_app, form, {})

    else:
        # TODO replace this ugly call, maybe per app?
        complete_registration(remote_app, form, user_info, token)
        return redirect(get_session_next_url(remote_app))


@ui_blueprint.route("/disconnect/<remote_app:remote_app>")
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


@ui_blueprint.route("/logout")
def post_logout():
    """Client logout view.

    This URL should be called by setting `SECURITY_POST_LOGOUT_VIEW = /oauth/logout`
    """
    remote_name = session.pop("OAUTHCLIENT_SESSION_REMOTE_NAME", None)
    clients = current_oauthclient.clients
    if remote_name and (logout_url := clients[remote_name].logout_url):
        return redirect(logout_url, code=302)

    return redirect("/")


@ui_blueprint.route("/login")
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
        app for app in remote_apps if not app.is_hidden and not app.link_only
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
        url = url_for("invenio_oauthclient.login", **redirect_args)
        return redirect(url)

    else:
        return base_login(*args, **kwargs)
