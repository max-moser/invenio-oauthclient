# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

from __future__ import annotations

from collections.abc import Iterable

from flask import current_app
from github3 import login
from github3.users import Email

from ..data import UserInfo
from .base import RemoteApp


class GitHubRemoteApp(RemoteApp):
    def _get_best_email(self, emails: Iterable[Email]) -> Email:
        """Get the "best" (i.e. verified/primary) email address from the account."""
        verified_emails = sorted(
            [e for e in emails if e.verified], key=lambda e: e.email
        )
        first_verified_email = next(verified_emails)
        primary_verified_email = next([e for e in verified_emails if e.primary], None)

        if primary_verified_email is not None:
            return primary_verified_email
        else:
            return first_verified_email

    def get_more_user_info(self, access_token: str) -> dict:
        try:
            session = login(token=access_token)
            user_info = session.me()

            return {
                "login": user_info.login,
                "name": user_info.name,
                "id": str(user_info.id),
                "email": self._get_best_email(session.emails()).email,
            }
        except Exception:
            current_app.logger.exception("Could not get user info from GitHub")
            return {}

    def parse_user_info(self, id_token: dict, extra_user_info: dict) -> UserInfo:
        return UserInfo(
            user={
                "active": True,
                "email": extra_user_info["email"],
                "username": extra_user_info["login"],
                "user_profile": {
                    "full_name": extra_user_info["name"],
                },
            },
            external_id=extra_user_info["id"],
            external_method=self.name,
            extra_data={
                # same as the old github contrib
                "login": extra_user_info["login"],
                "id": extra_user_info["id"],
            },
        )
