# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

"""Pre-configured remote application for EOSC AAI (OpenID Connect).

EOSC AAI is an OIDC/OAuth2 proxy. ``EOSCAAIRemoteApp`` builds on
``OIDCRemoteApp`` and additionally:

* enables PKCE (``code_challenge_method=S256``) by default, which the provider
  requires (authlib handles the verifier/challenge transparently, so no
  ``authorize``/``handle_oauth2_response`` overrides are needed),
* populates ``extra_data`` with EOSC-specific claims (``entitlements``,
  ``eunode_projects`` and the ``given_name``/``family_name`` profile fields).

Configure it with the provider's OIDC discovery URL::

    from invenio_oauthclient.remote_apps.eosc_aai import EOSCAAIRemoteApp

    OAUTHCLIENT_REMOTE_APPS = [
        EOSCAAIRemoteApp(
            name="eosc_aai",
            server_metadata=(
                "https://proxy.aai.open-science-cloud.ec.europa.eu/.well-known/openid-configuration"
            ),
            client_id="<CLIENT ID>",
            client_secret="<CLIENT SECRET>",
            scope="openid profile email entitlements",
            title="EOSC AAI",
        ),
    ]
"""

from __future__ import annotations

from ..data import UserInfo
from .oidc import OIDCRemoteApp


class EOSCAAIRemoteApp(OIDCRemoteApp):
    """OpenID Connect remote application for EOSC AAI."""

    def __init__(self, **kwargs):
        # EOSC AAI requires PKCE. authlib transparently generates the
        # ``code_verifier``/``code_challenge`` pair when ``S256`` is requested.
        client_kwargs = dict(kwargs.pop("client_kwargs", None) or {})
        client_kwargs.setdefault("code_challenge_method", "S256")
        kwargs["client_kwargs"] = client_kwargs
        super().__init__(**kwargs)

    def parse_user_info(self, id_token: dict, extra_user_info: dict) -> UserInfo:
        """Translate the received user information to what Invenio expects."""
        email = id_token.get("email") or extra_user_info.get("email") or ""
        full_name = id_token.get("name") or extra_user_info.get("name")
        given_name = id_token.get("given_name") or extra_user_info.get("given_name")
        family_name = id_token.get("family_name") or extra_user_info.get("family_name")
        sub = id_token.get("sub") or extra_user_info.get("sub") or ""

        user = {
            "active": True,
            "email": email,
            "user_profile": {
                "full_name": full_name,
                "given_name": given_name,
                "family_name": family_name,
            },
        }
        extra_data = {
            "sub": sub,
            "full_name": full_name,
            "given_name": given_name,
            "family_name": family_name,
            "email": email,
            "eunode_projects": (
                id_token.get("eunode_projects")
                or extra_user_info.get("eunode_projects")
                or []
            ),
            "entitlements": (
                id_token.get("entitlements") or extra_user_info.get("entitlements") or []
            ),
        }

        return UserInfo(user, sub, self.name, extra_data)
