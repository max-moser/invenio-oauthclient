# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

from __future__ import annotations

from abc import ABC

from authlib.integrations.flask_client import FlaskOAuth2App, OAuth
from authlib.oauth2.client import OAuth2Client

from .data import ServerMetadata, UserInfo


def info_serializer_handler(remote, token_user_info, user_info=None) -> UserInfo:
    """Serialize the account info response object.

    :param remote: The remote application.
    :param token_user_info: The content of the authorization token response.
    :param user_info: The response of the `user info` endpoint.
    :returns: A dictionary with serialized user information.
    """
    # fill out the information required by
    # 'invenio-accounts' and 'invenio-userprofiles'.
    #
    # note: "external_id": `preferred_username` should also work,
    #       as it is seemingly not editable in Keycloak

    # relevant for us: affiliation (to be massaged), uid (tiss id)
    user_info = user_info or {}  # prevent errors when accessing None.get(...)

    email = token_user_info.get("email") or user_info["email"]
    full_name = token_user_info.get("name") or user_info.get("name")
    username = token_user_info.get("preferred_username") or user_info.get(
        "preferred_username"
    )
    affiliations = (
        token_user_info.get("affiliation", user_info.get("affiliation")) or ""
    )

    user = {
        "active": True,
        "email": email,
        "username": (username or email.split("@")[0]).replace(".", "_"),
        "user_profile": {
            "full_name": full_name,
            "affiliations": affiliations,
        },
    }
    external_id = token_user_info["sub"]
    external_method = remote.name

    return UserInfo(user, external_id, external_method)


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
    ):
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope if isinstance(scope, str) else " ".join(scope)
        self.hidden = hidden
        self.link_only = link_only

        self.server_metadata_url = None
        self.server_metadata = None
        self.client = None
        self.registration_form = None

        if isinstance(server_metadata, str):
            self.server_metadata_url = server_metadata
        else:
            self.server_metadata = server_metadata

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
        )
        return self.client

    def register_compliance_fixes(self, session: OAuth2Client): ...

    def parse_user_info(self, id_token: dict, user_info: dict) -> UserInfo: ...


class OIDCRemoteApp(RemoteApp):
    def parse_user_info(self, id_token: dict, user_info: dict) -> UserInfo:
        user_info = info_serializer_handler(self, id_token, user_info)
        return user_info


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
