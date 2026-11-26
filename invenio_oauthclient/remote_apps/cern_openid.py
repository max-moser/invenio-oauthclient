# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

"""Pre-configured remote application for CERN (OpenID Connect).

CERN exposes an OIDC provider backed by Keycloak at
``https://auth.cern.ch/auth/realms/cern``. Unlike a stock OIDC provider it:

* uses the ``cern_upn`` claim as the external identifier (not ``sub``),
* lowers-cases the email and places the username under ``user_profile``,
* delivers a ``cern_roles`` (and ``cern_person_id``) set of claims.

``CERNRemoteApp`` handles the identifier and claim mapping. The *rejection*
of accounts whose roles are not allowed (the old
:class:`~invenio_oauthclient.errors.OAuthCERNRejectedAccountError` path) is
left as a TODO: it needs a decision point that the view can react to
(raising from ``parse_user_info`` is currently unhandled and would 500).

Configure it with the realm's OIDC discovery URL::

    from invenio_oauthclient.remote_apps.cern_openid import CERNRemoteApp

    OAUTHCLIENT_REMOTE_APPS = [
        CERNRemoteApp(
            name="cern_openid",
            server_metadata=(
                "https://auth.cern.ch/auth/realms/cern/.well-known/openid-configuration"
            ),
            client_id="<CLIENT ID>",
            client_secret="<CLIENT SECRET>",
            scope="openid email profile",
            title="CERN",
        ),
    ]
"""

from __future__ import annotations

from ..data import GroupInfo, UserInfo
from .oidc import OIDCRemoteApp


class CERNRemoteApp(OIDCRemoteApp):
    """OpenID Connect remote application for CERN."""

    def parse_user_info(self, id_token: dict, extra_user_info: dict) -> UserInfo:
        """Translate the received user information to what Invenio expects."""
        email = (id_token.get("email") or extra_user_info.get("email") or "").lower()
        username = (
            id_token.get("preferred_username")
            or extra_user_info.get("preferred_username")
            or email.split("@")[0]
        )
        full_name = id_token.get("name") or extra_user_info.get("name")

        # CERN's external identifier is the CERN user principle name, not ``sub``.
        external_id = (
            id_token.get("cern_upn")
            or extra_user_info.get("cern_upn")
            or id_token.get("sub")
            or extra_user_info.get("sub")
            or ""
        )

        roles = id_token.get("cern_roles") or extra_user_info.get("cern_roles") or []
        person_id = id_token.get("cern_person_id") or extra_user_info.get("cern_person_id")

        user = {
            "active": True,
            "email": email,
            "username": username.replace(".", "_"),
            "user_profile": {
                "full_name": full_name,
            },
        }
        extra_data = {
            # ``finalize_login`` additionally ``setdefault``s ``external_id``.
            "person_id": person_id,
            "roles": roles,
        }

        return UserInfo(user, external_id, self.name, extra_data)

    def get_groups(self, user_info: UserInfo, access_token: str = "") -> list[GroupInfo]:
        """Return the CERN roles as unmanaged groups."""
        roles = user_info.extra_data.get("roles", [])
        return [GroupInfo(id=role, name=role, description="") for role in roles]
