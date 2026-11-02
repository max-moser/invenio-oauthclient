# SPDX-FileCopyrightText: 2016-2018 CERN.
# SPDX-License-Identifier: MIT

"""Create oauthclient branch."""


# revision identifiers, used by Alembic.
revision = "44ab9963e8cf"
down_revision = None
branch_labels = ("invenio_oauthclient",)
depends_on = "dbdbc1b19cf2"


def upgrade():
    """Upgrade database."""


def downgrade():
    """Downgrade database."""
