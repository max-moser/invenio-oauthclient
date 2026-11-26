# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

"""Pre-configured remote application for enabling sign in/up with Globus.

Globus is a plain OAuth2 provider (no ``id_token``). The user info is fetched
from the Globus userinfo endpoint (``{api_base_url}oauth2/userinfo``) and the
user identifier (a Globus UUID) from the same endpoint queried with a
``usernames`` parameter.

Configure it with the fixed OAuth2 endpoints::

    from invenio_oauthclient.remote_apps.globus import GlobusRemoteApp
    from invenio_oauthclient.data import ServerMetadata

    OAUTHCLIENT_REMOTE_APPS = [
        GlobusRemoteApp(
            name="globus",
            server_metadata=ServerMetadata(
                access_token_url="https://auth.globus.org/v2/oauth2/token",
                authorize_url="https://auth.globus.org/v2/oauth2/authorize",
                api_base_url="https://auth.globus.org/v2/",
            ),
            client_id="<CLIENT ID>",
            client_secret="<CLIENT SECRET>",
            scope="openid email profile",
            title="Globus",
        ),
    ]
"""

from __future__ import annotations

import requests
from flask import current_app

from ..data import UserInfo
from .base import RemoteApp


class GlobusRemoteApp(RemoteApp):
    """OAuth2 remote application for Globus."""

    def _get(self, url: str, access_token: str) -> dict:
        """GET ``url`` with the bearer token, returning the JSON payload."""
        response = requests.get(
            url, headers={"Authorization": f"Bearer {access_token}"}
        )
        response.raise_for_status()
        return response.json()

    def _get_user_id(self, base_url: str, access_token: str, username: str) -> str:
        """Fetch the Globus UUID for the given username/email."""
        url = f"{base_url}oauth2/userinfo?usernames={username}"
        data = self._get(url, access_token)
        return data["identities"][0]["id"]

    def get_more_user_info(self, access_token: str) -> dict:
        """Return the Globus user info plus the Globus UUID identifier."""
        try:
            base_url = self.server_metadata.get("api_base_url", "")
            user_info = self._get(f"{base_url}oauth2/userinfo", access_token)

            preferred_username = user_info.get("preferred_username") or ""
            username = preferred_username
            if "@" in username:
                username = username.split("@")[0]
            user_id = self._get_user_id(
                base_url, access_token, preferred_username
            )

            return {
                "email": user_info.get("email"),
                "username": username,
                "full_name": user_info.get("name"),
                "id": user_id,
            }
        except (requests.HTTPError, KeyError, IndexError):
            current_app.logger.exception("Could not get user info from Globus")
            return {}

    def parse_user_info(self, id_token: dict, extra_user_info: dict) -> UserInfo:
        """Translate the received user information to what Invenio expects."""
        email = extra_user_info.get("email")
        username = extra_user_info.get("username")
        full_name = extra_user_info.get("full_name")
        external_id = extra_user_info.get("id")

        user = {
            "active": True,
            "email": email,
            "username": username,
            "user_profile": {
                "full_name": full_name,
            },
        }
        extra_data = {"login": username}

        return UserInfo(user, external_id, self.name, extra_data)
