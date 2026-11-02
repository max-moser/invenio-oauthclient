# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

from __future__ import annotations

from abc import ABC
from dataclasses import asdict
from datetime import datetime

from authlib.integrations.flask_client import FlaskOAuth2App, OAuth
from authlib.oauth2.client import OAuth2Client
from invenio_accounts.models import User
from invenio_db import db

from ..data import LazyDict, ServerMetadata, UserInfo
from ..models import RemoteAccount, RemoteToken, UserIdentity


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
        client_kwargs: dict | None = None,
        logout_url: str | None = None,
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
        self.client_kwargs = client_kwargs or {}
        self.logout_url = logout_url

        if isinstance(server_metadata, str):
            self.server_metadata_url = server_metadata
        else:
            self.server_metadata = asdict(server_metadata)
            self.client_kwargs.update(self.server_metadata.pop("client_kwargs", {}))

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
                **self.client_kwargs,
            },
            compliance_fix=self.register_compliance_fixes,
            **self.server_metadata,
        )
        return self.client

    def register_compliance_fixes(self, session: OAuth2Client):
        """Register compliance fixes for the ``authlib`` client."""

    def get_more_user_info(self, access_token: str) -> dict:
        """Fetch more user info if the ID token was not enough.

        This method will be used lazily if the initially provided user information
        (e.g. via the ID token) is not enough.
        In the case of OIDC, this will typically query the ``userinfo`` endpoint.
        For OAuth2 applications, this may require specific handling.
        """

    def parse_user_info(self, id_token: dict, extra_user_info: LazyDict) -> UserInfo:
        """Translate the received user information to what Invenio expects.

        The provided ``user_info`` lazy dictionary will only call its backing source
        if it gets accessed.
        So if the information from the ``id_token`` is sufficient, simply not accessing
        the ``extra_user_info`` values may save a network round trip.
        """

    def finalize_login(
        self,
        user: User,
        user_info: UserInfo,
        access_token: str,
        refresh_token: str | None = None,
        expires_at: datetime | None = None,
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
            remote_token.update_token(
                token=access_token,
                secret="",
                refresh_token=refresh_token,
                expires=expires_at,
            )
            remote_token.remote_account.extra_data = user_info.extra_data
        else:
            RemoteToken.create(
                user.id,
                self.client_id,
                token=access_token,
                extra_data=user_info.extra_data,
                refresh_token=refresh_token,
                expires=expires_at,
                secret="",
            )

    def handle_disconnect(self, remote_account: RemoteAccount | None): ...
