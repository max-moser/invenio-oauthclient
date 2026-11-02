# SPDX-FileCopyrightText: 2023 CERN.
# SPDX-License-Identifier: MIT

"""Tasks."""

from celery import shared_task
from flask import current_app
from invenio_accounts.models import Role
from invenio_accounts.proxies import current_datastore
from invenio_db import db
from invenio_i18n import gettext as _


def _role_needs_update(role_obj, new_role_dict):
    """Checks if role needs to be updated."""
    return bool(
        role_obj.name != new_role_dict.get("name")
        or role_obj.description != new_role_dict.get("description")
    )


def create_or_update_roles(groups, persist_every=500):
    """Create/update DB roles based on the groups provided."""
    roles_ids = set()
    processed_count = 0

    for group in groups:
        try:
            current_app.logger.debug(f"Syncing role: {group['name']}")

            existing_role = current_datastore.find_role_by_id(group["id"])
            if existing_role and existing_role.is_managed:
                current_app.logger.exception(
                    _(
                        "Error while syncing roles: A managed role with id: %(group_id)s already exists",
                        group_id=group["id"],
                    )
                )
                continue

            existing_role_by_name = current_datastore.find_role(group["name"])
            if existing_role_by_name and existing_role_by_name.is_managed:
                current_app.logger.exception(
                    _(
                        "Error while syncing roles: A managed role with name: %(group_name)s already exists",
                        group_name=group["name"],
                    )
                )
                continue

            with db.session.begin_nested():
                if not existing_role:
                    role = current_datastore.create_role(
                        id=group["id"],
                        name=group["name"],
                        description=group.get("description"),
                        is_managed=False,
                    )
                    roles_ids.add(role.id)
                elif existing_role and _role_needs_update(existing_role, group):
                    role_to_update = Role(
                        id=group["id"],
                        name=group["name"],
                        description=group.get("description"),
                        is_managed=False,
                    )
                    role = current_datastore.update_role(role_to_update)
                    roles_ids.add(role.id)
                else:
                    roles_ids.add(existing_role.id)

            processed_count += 1

            # Commit every `persist_every` iterations
            if processed_count % persist_every == 0:
                current_datastore.commit()

        except Exception as e:
            current_app.logger.error(
                f"Error while syncing roles: {group['name']}. Error: {e}"
            )
            continue

    # Final commit for any remaining uncommitted changes
    current_datastore.commit()
    return roles_ids


@shared_task
def create_or_update_roles_task(groups):
    """Task to create/update DB roles based on the groups provided."""
    create_or_update_roles(groups)
