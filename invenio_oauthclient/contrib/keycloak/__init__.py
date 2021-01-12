# -*- coding: utf-8 -*-
#
# Copyright (C) 2020-2021 TU Wien.
#
# Invenio-Keycloak is free software; you can redistribute it and/or modify it
# under the terms of the MIT License; see LICENSE file for more details.

"""Toolkit for creating remote apps that enable sign in/up with Keycloak.

**Note:** In contrast to e.g. GitHub, Keycloak is a self-hosted solution that
requires a bit of configuration to allow OAuth client applications, such as
Invenio. An explanation of how to set up Keycloak is out of scope for this
document, where we focus on configuring Invenio.


0. Set up a Keycloak server and make sure it is configured appropriately,
   i.e. a client application for Invenio is configured in a realm in Keycloak.

1. Add the following items to your configuration (``invenio.cfg``).
   The ``KeycloakSettingsHelper`` class can be used to help with setting up
   the configuration values:

   .. code-block:: python

        from invenio_oauthclient.contrib import keycloak as k

        helper = k.KeycloakSettingsHelper(
            base_url="http://yourkeycloakserver.com:8080",
            realm="invenio"
        )

        # create the configuration for Keycloak
        # because the URLs usually follow a certain schema, the settings helper
        # can be used to more easily build the configuration values:
        OAUTHCLIENT_KEYCLOAK_REALM_URL = helper.realm_url
        OAUTHCLIENT_KEYCLOAK_USER_INFO_URL = helper.user_info_url

        # Keycloak uses JWTs (https://jwt.io/) for their tokens, which
        # contain information about the target audience (AUD)
        # verification of the expected AUD value can be configured with:
        OAUTHCLIENT_KEYCLOAK_VERIFY_AUD = True
        OAUTHCLIENT_KEYCLOAK_AUD = "invenio"

        # the settings helper can also be used to create the REMOTE APP dicts
        OAUTHCLIENT_KEYCLOAK_REMOTE_APP = helper.remote_app()
        OAUTHCLIENT_KEYCLOAK_REMOTE_REST_APP = helper.remote_rest_app()

        # add Keycloak to the dictionary of remote apps
        OAUTHCLIENT_REMOTE_APPS = dict(
            keycloak=OAUTHCLIENT_KEYCLOAK_REMOTE_APP,
            # ...
        )

        # to automatically set a user's email address on sign-up, the
        # registration forms have to be extended
        USERPROFILES_EXTEND_SECURITY_FORMS = True

2. Grab the *Client ID* and *Client Secret* from the client application in
   Keycloak and add them to your instance configuration (``invenio.cfg``):

   .. code-block:: python

        KEYCLOAK_APP_CREDENTIALS = dict(
            consumer_key='<CLIENT ID>',
            consumer_secret='<CLIENT SECRET>',
        )

3. Now go to ``CFG_SITE_SECURE_URL/oauth/login/keycloak/`` (e.g.
   https://localhost:4000/oauth/login/keycloak/) and log in.

4. After authenticating successfully, you should see Keycloak listed under
   Linked accounts: https://localhost:4000/account/settings/linkedaccounts/
"""

from .handlers import disconnect_handler, disconnect_rest_handler, \
    info_handler, setup_handler
from .settings import OAUTHCLIENT_KEYCLOAK_AUD, \
    OAUTHCLIENT_KEYCLOAK_REALM_URL, OAUTHCLIENT_KEYCLOAK_REMOTE_APP, \
    OAUTHCLIENT_KEYCLOAK_REMOTE_REST_APP, OAUTHCLIENT_KEYCLOAK_USER_INFO_URL, \
    OAUTHCLIENT_KEYCLOAK_VERIFY_AUD, KeycloakSettingsHelper

__all__ = (
    "disconnect_handler",
    "disconnect_rest_handler",
    "info_handler",
    "setup_handler",
    "KeycloakSettingsHelper",
    "OAUTHCLIENT_KEYCLOAK_AUD",
    "OAUTHCLIENT_KEYCLOAK_REALM_URL",
    "OAUTHCLIENT_KEYCLOAK_REMOTE_APP",
    "OAUTHCLIENT_KEYCLOAK_REMOTE_REST_APP",
    "OAUTHCLIENT_KEYCLOAK_USER_INFO_URL",
    "OAUTHCLIENT_KEYCLOAK_VERIFY_AUD",
)
