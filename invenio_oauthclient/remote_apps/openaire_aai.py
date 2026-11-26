# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

# TODO the openid-configuration entry does not exist
"""Pre-configured remote application for OpenAIRE AAI (OpenID Connect).

OpenAIRE AAI is an OIDC provider. ``OpenAIREAARemoteApp`` builds on
``OIDCRemoteApp`` and stores the provider's ``sub`` claim in ``extra_data``
under the ``id`` key (backwards compatible with the old contrib).

Configure it with the provider's OIDC discovery URL::

    from invenio_oauthclient.remote_apps.openaire_aai import OpenAIREAARemoteApp

    OAUTHCLIENT_REMOTE_APPS = [
        OpenAIREAARemoteApp(
            name="openaire_aai",
            server_metadata=(
                "https://aai.openaire.eu/.well-known/openid-configuration"
            ),
            client_id="<CLIENT ID>",
            client_secret="<CLIENT SECRET>",
            scope="openid profile email orcid",
            title="OpenAIRE",
        ),
    ]
"""

from __future__ import annotations

from ..data import UserInfo
from .oidc import OIDCRemoteApp


class OpenAIREAARemoteApp(OIDCRemoteApp):
    """OpenID Connect remote application for OpenAIRE AAI."""

    def parse_user_info(self, id_token: dict, extra_user_info: dict) -> UserInfo:
        """Translate the received user information to what Invenio expects."""
        user_info = super().parse_user_info(id_token, extra_user_info)

        sub = id_token.get("sub") or extra_user_info.get("sub")
        # Backwards compatible with the old contrib, which stored ``id``.
        user_info.extra_data.setdefault("id", sub)

        return user_info
