# SPDX-FileCopyrightText: 2026 TU Wien.
# SPDX-License-Identifier: MIT

from __future__ import annotations

from werkzeug.routing import BaseConverter, ValidationError


class RemoteAppConverter(BaseConverter):
    """Endpoint converter validating that the remote app is known."""

    def to_python(self, value: str) -> RemoteApp:
        try:
            return current_oauthclient.clients[value]
        except KeyError:
            raise ValidationError(f"{value} is not a known remote app")

    def to_url(self, value: RemoteApp | str) -> str:
        if isinstance(value, RemoteApp):
            return value.name
        return value
