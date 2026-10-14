# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

from __future__ import annotations

from abc import ABC
from dataclasses import asdict

from authlib.integrations.flask_client import FlaskOAuth2App, OAuth
from authlib.oauth2.client import OAuth2Client
from invenio_accounts.models import User
from invenio_db import db

from ..models import RemoteAccount, RemoteToken, UserIdentity
from .data import ServerMetadata, UserInfo


class RemoteApp(ABC):
    def __init__(
        self,
        name: str,
        server_metadata: str | ServerMetadata,
        client_id: str,
        client_secret: str,
        scope: list[str] | str,
        hidden: bool = False,
        link_only: bool = False,
        title: str = "",
        description: str = "",
        icon: str = "",
    ):
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope if isinstance(scope, str) else " ".join(scope)
        self.hidden = hidden
        self.link_only = link_only

        self.title = title or self.name.title()
        self.description = description
        self.icon = icon

        self.server_metadata_url = None
        self.server_metadata = {}
        self.client = None
        self.registration_form = None

        if isinstance(server_metadata, str):
            self.server_metadata_url = server_metadata
        else:
            self.server_metadata = asdict(server_metadata)

    def register(self, oauth: OAuth) -> FlaskOAuth2App:
        # TODO use server_metadata if not server_metadata_url
        self.client = oauth.register(
            self.name,
            overwrite=False,
            server_metadata_url=self.server_metadata_url,
            client_id=self.client_id,
            client_secret=self.client_secret,
            client_kwargs={
                "scope": self.scope,
            },
            compliance_fix=self.register_compliance_fixes,
            **self.server_metadata,
        )
        return self.client

    def register_compliance_fixes(self, session: OAuth2Client): ...

    def parse_user_info(
        self, id_token: dict, user_info: dict, access_token: str
    ) -> UserInfo: ...

    def finalize_login(
        self, user: User, user_info: UserInfo, access_token: str
    ) -> None:
        user_identity = (
            db.session.query(UserIdentity)
            .filter(UserIdentity.user == user, UserIdentity.method == self.name)
            .one_or_none()
        )
        if user_identity:
            user_identity.id = user_info.external_id
        else:
            UserIdentity.create(user, self.name, user_info.external_id)

        # Explicitly set the external ID in the extra data, to make it easier later
        # to query for the UserIdentity via the RemoteAccount
        user_info.extra_data.setdefault("external_id", user_info.external_id)
        if remote_token := RemoteToken.get(user.id, self.client_id):
            remote_token.update_token(token=access_token, secret="")
            remote_token.remote_account.extra_data = user_info.extra_data
        else:
            RemoteToken.create(
                user.id,
                self.client_id,
                token=access_token,
                extra_data=user_info.extra_data,
                secret="",
            )

    def handle_disconnect(self, remote_account: RemoteAccount | None): ...


class OIDCRemoteApp(RemoteApp):
    def parse_user_info(
        self, id_token: dict, user_info: dict, access_token: str
    ) -> UserInfo:
        user_info = user_info or {}  # prevent errors when accessing None.get(...)

        email = id_token.get("email") or user_info["email"]
        full_name = id_token.get("name") or user_info.get("name")
        username = id_token.get("preferred_username") or user_info.get(
            "preferred_username"
        )
        affiliations = id_token.get("affiliation", user_info.get("affiliation")) or ""

        user = {
            "active": True,
            "email": email,
            "username": (username or email.split("@")[0]).replace(".", "_"),
            "user_profile": {
                "full_name": full_name,
                "affiliations": affiliations,
            },
        }
        external_id = id_token["sub"]
        external_method = self.name
        extra_data = {}

        return UserInfo(user, external_id, external_method, extra_data)


class SDK42RemoteApp(OIDCRemoteApp):
    def register_compliance_fixes(self, session: OAuth2Client):
        def _set_missing_access_token(resp):
            data = resp.json()
            data["access_token"] = "some_access_token"
            resp.json = lambda: data
            return resp

        session.register_compliance_hook(
            "access_token_response", _set_missing_access_token
        )
