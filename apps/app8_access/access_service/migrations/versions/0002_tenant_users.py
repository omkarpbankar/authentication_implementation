"""Records which users belong to which tenant.

The users table is shared across tenants, so without this table an admin in one tenant could
see people from every other tenant. Row-level security on this table closes that gap.
"""

from alembic import op

revision = "0002"
down_revision = "0001"


def upgrade() -> None:
    op.execute("""
    CREATE TABLE tenant_users (
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        user_id uuid NOT NULL REFERENCES users (id),
        PRIMARY KEY (tenant_id, user_id)
    )""")
    op.execute("ALTER TABLE tenant_users ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tenant_users FORCE ROW LEVEL SECURITY")
    op.execute("""
    CREATE POLICY tenant_isolation ON tenant_users
        USING (tenant_id = app_tenant_id())
        WITH CHECK (tenant_id = app_tenant_id())
    """)
    op.execute("GRANT SELECT, INSERT ON tenant_users TO access_app")


def downgrade() -> None:
    op.execute("DROP TABLE tenant_users")
