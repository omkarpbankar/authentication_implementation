"""Tenants, users, memberships, and tenant-owned data."""

from alembic import op

revision = "0001"
down_revision = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE tenants (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        slug text NOT NULL UNIQUE,
        name text NOT NULL,
        status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
        created_at timestamptz NOT NULL DEFAULT now()
    )""")
    op.execute("""
    CREATE TABLE users (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        email text NOT NULL DEFAULT '',
        name text NOT NULL DEFAULT '',
        created_at timestamptz NOT NULL DEFAULT now()
    )""")
    # One person can sign in through several providers.
    op.execute("""
    CREATE TABLE user_identities (
        issuer text NOT NULL,
        subject text NOT NULL,
        user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        PRIMARY KEY (issuer, subject)
    )""")
    # Maps a provider's idea of a tenant to our own tenant_id.
    op.execute("""
    CREATE TABLE tenant_idp_connections (
        issuer text NOT NULL,
        external_tenant_id text NOT NULL,
        tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
        PRIMARY KEY (issuer, external_tenant_id)
    )""")
    op.execute("""
    CREATE TABLE tenant_domains (
        domain text PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
        verified boolean NOT NULL DEFAULT false,
        sso_enforced boolean NOT NULL DEFAULT false
    )""")
    op.execute("""
    CREATE TABLE memberships (
        tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
        user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        role text NOT NULL DEFAULT 'viewer',
        clearance integer NOT NULL DEFAULT 0,
        PRIMARY KEY (tenant_id, user_id)
    )""")
    op.execute("CREATE INDEX memberships_user ON memberships (user_id)")
    # tenant_id comes first in each key, because every query filters on it.
    op.execute("""
    CREATE TABLE projects (
        tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        name text NOT NULL,
        PRIMARY KEY (tenant_id, id),
        UNIQUE (tenant_id, name)
    )""")
    # The composite foreign key makes it impossible to point at another tenant's project.
    op.execute("""
    CREATE TABLE documents (
        tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
        id uuid NOT NULL DEFAULT gen_random_uuid(),
        project_id uuid NOT NULL,
        title text NOT NULL,
        body text NOT NULL DEFAULT '',
        owner_id uuid NOT NULL REFERENCES users (id),
        confidential boolean NOT NULL DEFAULT false,
        PRIMARY KEY (tenant_id, id),
        FOREIGN KEY (tenant_id, project_id) REFERENCES projects (tenant_id, id) ON DELETE CASCADE
    )""")
    op.execute("""
    CREATE TABLE audit_log (
        tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
        id bigint GENERATED ALWAYS AS IDENTITY,
        actor_id uuid,
        action text NOT NULL,
        target text NOT NULL DEFAULT '',
        at timestamptz NOT NULL DEFAULT now(),
        PRIMARY KEY (tenant_id, id)
    )""")
    # Time-boxed permission for one support person to view one tenant.
    op.execute("""
    CREATE TABLE support_grants (
        tenant_id uuid NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
        support_user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        reason text NOT NULL,
        expires_at timestamptz NOT NULL,
        PRIMARY KEY (tenant_id, support_user_id)
    )""")

    op.execute("""
    GRANT SELECT, INSERT, UPDATE, DELETE
    ON tenants, users, user_identities, tenant_idp_connections, tenant_domains,
       memberships, projects, documents
    TO platform_app""")
    # The audit log is append-only for the app: no update, and no delete.
    op.execute("GRANT SELECT, INSERT ON audit_log TO platform_app")
    op.execute("GRANT INSERT, SELECT ON support_grants TO platform_app")
    op.execute("""
    GRANT SELECT ON tenants, users, projects, documents, support_grants TO platform_support
    """)
    op.execute("GRANT SELECT, INSERT ON audit_log TO platform_support")


def downgrade() -> None:
    op.execute("""
    DROP TABLE support_grants, audit_log, documents, projects, memberships, tenant_domains,
               tenant_idp_connections, user_identities, users, tenants
    """)
