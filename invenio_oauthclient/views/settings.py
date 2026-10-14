# SPDX-FileCopyrightText: 2015-2018 CERN.
# SPDX-FileCopyrightText: 2024 Graz University of Technology.
# SPDX-License-Identifier: MIT

"""Account settings blueprint for oauthclient."""

from dataclasses import dataclass
from operator import itemgetter

from flask import Blueprint, current_app, render_template
from flask_login import current_user, login_required

from ..models import RemoteAccount
from ..proxies import current_oauthclient

blueprint = Blueprint(
    "invenio_oauthclient_settings",
    __name__,
    url_prefix="/account/settings/linkedaccounts",
    static_folder="../static",
    template_folder="../templates",
)


@dataclass
class RemoteInfo:
    appid: str
    title: str
    icon: str
    description: str
    link_only: bool
    account: RemoteAccount


@blueprint.route("/", methods=["GET", "POST"])
@login_required
def index():
    """List linked accounts."""
    services: list[RemoteInfo] = []

    remote_apps = current_oauthclient.clients.values()
    visible_remote_apps = [app for app in remote_apps if not app.hidden]

    # Fetch already linked accounts
    accounts = RemoteAccount.query.filter_by(user_id=current_user.get_id()).all()
    accounts_by_app = {a.client_id: a for a in accounts}

    for remote_app in visible_remote_apps:
        remote_info = RemoteInfo(
            appid=remote_app.name,
            title=remote_app.title,
            icon=remote_app.icon,
            description=remote_app.description,
            link_only=remote_app.link_only,
            account=accounts_by_app.get(remote_app.client_id, None),
        )
        services.append(remote_info)

    # Sort according to title
    services.sort(key=lambda s: s.title)

    # Check if local login is possible
    local_login_enabled = current_app.config.get("ACCOUNTS_LOCAL_LOGIN_ENABLED", True)
    password_set = current_user.password is not None
    local_login_possible = local_login_enabled and password_set

    return render_template(
        "invenio_oauthclient/settings/index.html",
        services=services,
        only_external_login=not local_login_possible,
    )
