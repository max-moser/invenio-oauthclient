# SPDX-FileCopyrightText: 2015-2018 CERN.
# SPDX-License-Identifier: MIT

"""Blueprints for oauthclient."""

from .rest import rest_blueprint
from .settings import blueprint as settings_blueprint
from .ui import ui_blueprint

blueprints = [
    rest_blueprint,
    settings_blueprint,
    ui_blueprint,
]
