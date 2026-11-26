# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

"""Pre-configured remote application for Keycloak (OpenID Connect).

Keycloak is a self-hosted OIDC provider. ``KeycloakRemoteApp`` builds on
``OIDCRemoteApp`` and additionally:

* stores the Keycloak user identifier (the ``sub`` claim) in ``extra_data``
  under the ``keycloak_id`` key (backwards compatible with the old contrib),
* synchronizes the user's realm roles (``realm_access.roles``) as *unmanaged*
  Invenio roles via the :meth:`RemoteApp.get_groups` hook.

It is expected to be configured with the realm's OIDC discovery URL::

    from invenio_oauthclient.remote_apps.keycloak import KeycloakRemoteApp

    OAUTHCLIENT_REMOTE_APPS = [
        KeycloakRemoteApp(
            name="keycloak",
            server_metadata=(
                "https://keycloak.example.org/realms/myrealm/"
                ".well-known/openid-configuration"
            ),
            client_id="<CLIENT ID>",
            client_secret="<CLIENT SECRET>",
            scope="openid email profile",
            title="Keycloak",
            icon="fa fa-key",
        ),
    ]
"""

from __future__ import annotations

from ..data import GroupInfo, UserInfo
from .oidc import OIDCRemoteApp


class KeycloakRemoteApp(OIDCRemoteApp):
    """OpenID Connect remote application for Keycloak."""

    def parse_user_info(self, id_token: dict, extra_user_info: dict) -> UserInfo:
        """Translate the received user information to what Invenio expects.

        Uses the default OIDC claim mapping and stores the Keycloak ID plus the
        realm roles in ``extra_data``.
        """
        user_info = super().parse_user_info(id_token, extra_user_info)

        sub = id_token.get("sub") or extra_user_info.get("sub")
        user_info.extra_data.setdefault("keycloak_id", sub)

        # Keycloak delivers the realm roles in the ID token under ``realm_access``.
        realm_access = (
            id_token.get("realm_access") or extra_user_info.get("realm_access") or {}
        )
        user_info.extra_data["roles"] = realm_access.get("roles", []) or []

        return user_info

    def get_groups(self, user_info: UserInfo, access_token: str = "") -> list[GroupInfo]:
        """Return the Keycloak realm roles as unmanaged groups."""
        roles = user_info.extra_data.get("roles", [])
        return [GroupInfo(id=role, name=role, description="") for role in roles]
