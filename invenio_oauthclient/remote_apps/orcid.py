# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

"""Pre-configured remote application for enabling sign in/up with ORCID.

ORCID is a plain OAuth2 provider (no ``id_token``). The user's ORCID iD and
name are returned **in the OAuth token response** itself (``scope``
``/authenticate``), not in a separate userinfo endpoint. ``ORCIDRemoteApp``
therefore reads them from the registered client's token after
``authorize_access_token``.

Configure it with the fixed OAuth2 endpoints::

    from invenio_oauthclient.remote_apps.orcid import ORCIDRemoteApp
    from invenio_oauthclient.data import ServerMetadata

    OAUTHCLIENT_REMOTE_APPS = [
        ORCIDRemoteApp(
            name="orcid",
            server_metadata=ServerMetadata(
                access_token_url="https://orcid.org/oauth/token",
                authorize_url="https://orcid.org/oauth/authorize",
                api_base_url="https://pub.orcid.org/v1.2/",
                authorize_params={"show_login": "true"},
            ),
            client_id="<CLIENT ID>",
            client_secret="<CLIENT SECRET>",
            scope="/authenticate",
            title="ORCID",
        ),
    ]
"""

from __future__ import annotations

from ..data import UserInfo
from .base import RemoteApp


class ORCIDRemoteApp(RemoteApp):
    """OAuth2 remote application for ORCID."""

    def get_more_user_info(self, access_token: str) -> dict:
        """Return the ORCID iD and name found in the OAuth token response.

        ORCID does not expose a userinfo endpoint; with the ``/authenticate``
        scope it returns ``orcid`` and ``name`` alongside the access token.
        """
        token = getattr(self.client, "token", {}) or {}
        return {
            "orcid": token.get("orcid"),
            "name": token.get("name"),
        }

    def parse_user_info(self, id_token: dict, extra_user_info: dict) -> UserInfo:
        """Translate the received user information to what Invenio expects."""
        orcid = id_token.get("orcid") or extra_user_info.get("orcid")
        full_name = id_token.get("name") or extra_user_info.get("name")

        # ORCID's public API does not expose the user's email; it must be
        # provided by the user during sign-up.
        user = {
            "active": True,
            "user_profile": {
                "full_name": full_name,
            },
        }
        extra_data = {
            "orcid": orcid,
            "full_name": full_name,
        }

        return UserInfo(user, orcid, self.name, extra_data)
