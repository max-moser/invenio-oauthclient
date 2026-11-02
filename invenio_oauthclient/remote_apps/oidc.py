# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

from __future__ import annotations

from authlib.oauth2.client import OAuth2Client
from flask import current_app
from requests import HTTPError

from ..data import UserInfo
from .base import RemoteApp


class OIDCRemoteApp(RemoteApp):
    def get_more_user_info(self, access_token: str) -> dict:
        try:
            remote_user_info = self.client.userinfo()
            return dict(remote_user_info)
        except HTTPError as e:
            current_app.logger.error(e)
            return {}

    def parse_user_info(self, id_token: dict, extra_user_info: dict) -> UserInfo:
        email = id_token.get("email") or extra_user_info["email"]
        full_name = id_token.get("name") or extra_user_info.get("name")
        username = id_token.get("preferred_username") or extra_user_info.get(
            "preferred_username"
        )
        affiliations = (
            id_token.get("affiliation") or extra_user_info.get("affiliation") or ""
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
        external_id = id_token.get("sub") or extra_user_info["sub"]
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
