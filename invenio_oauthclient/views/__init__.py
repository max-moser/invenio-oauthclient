# SPDX-FileCopyrightText: 2015-2018 CERN.
# SPDX-License-Identifier: MIT

"""Blueprints for oauthclient."""

from .settings import blueprint as settings_blueprint
from .views import blueprint

blueprints = [
    blueprint,
    settings_blueprint,
]
