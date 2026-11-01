"""Applications, tiers, grants, groups, requests, admins, and the audit log."""

from alembic import op

revision = "0001"
down_revision = None

TENANT_TABLES = [
    "user_app_access",
    "groups",
    "group_members",
    "group_app_access",
    "tenant_app_licenses",
    "access_requests",
    "admin_roles",
    "access_audit_log",
]


def upgrade() -> None:
    op.execute("""
    CREATE TABLE tenants (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        slug text NOT NULL UNIQUE,
        name text NOT NULL,
        status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended'))
    )""")
    op.execute("""
    CREATE TABLE users (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        issuer text NOT NULL,
        subject text NOT NULL,
        email text NOT NULL DEFAULT '',
        name text NOT NULL DEFAULT '',
        status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
        last_seen_at timestamptz,
        UNIQUE (issuer, subject)
    )""")
    # Rows here are never deleted, so an application ID can never be reused.
    op.execute("""
    CREATE TABLE applications (
        id uuid PRIMARY KEY,
        app_key text NOT NULL UNIQUE,
        name text NOT NULL,
        status text NOT NULL DEFAULT 'active'
            CHECK (status IN ('active', 'maintenance', 'retired'))
    )""")
    op.execute("""
    CREATE TABLE application_clients (
        issuer text NOT NULL,
        client_id text NOT NULL,
        application_id uuid NOT NULL REFERENCES applications (id),
        environment text NOT NULL DEFAULT 'local',
        PRIMARY KEY (issuer, client_id)
    )""")
    op.execute("""
    CREATE TABLE tiers (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        application_id uuid NOT NULL REFERENCES applications (id),
        key text NOT NULL,
        rank integer NOT NULL,
        UNIQUE (application_id, key),
        UNIQUE (application_id, rank)
    )""")
    op.execute("""
    CREATE TABLE features (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        application_id uuid NOT NULL REFERENCES applications (id),
        key text NOT NULL UNIQUE
    )""")
    op.execute("""
    CREATE TABLE tier_features (
        tier_id uuid NOT NULL REFERENCES tiers (id) ON DELETE CASCADE,
        feature_id uuid NOT NULL REFERENCES features (id) ON DELETE CASCADE,
        limit_value integer,
        PRIMARY KEY (tier_id, feature_id)
    )""")
    # RESTRICT is what blocks deleting a tier that users still hold.
    op.execute("""
    CREATE TABLE user_app_access (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        user_id uuid NOT NULL REFERENCES users (id),
        application_id uuid NOT NULL REFERENCES applications (id),
        tier_id uuid NOT NULL REFERENCES tiers (id) ON DELETE RESTRICT,
        status text NOT NULL DEFAULT 'active'
            CHECK (status IN ('active', 'suspended', 'revoked')),
        starts_at timestamptz,
        expires_at timestamptz,
        source text NOT NULL DEFAULT 'admin'
            CHECK (source IN ('admin', 'request', 'bulk', 'scim', 'billing')),
        granted_by uuid REFERENCES users (id),
        reason text NOT NULL DEFAULT '',
        reviewed_at timestamptz,
        version integer NOT NULL DEFAULT 1
    )""")
    # Only one live grant per user and app. Revoked rows stay as history.
    op.execute("""
    CREATE UNIQUE INDEX one_live_grant ON user_app_access (tenant_id, user_id, application_id)
    WHERE status <> 'revoked'
    """)
    op.execute("""
    CREATE TABLE groups (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        name text NOT NULL,
        UNIQUE (tenant_id, name)
    )""")
    op.execute("""
    CREATE TABLE group_members (
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        group_id uuid NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
        user_id uuid NOT NULL REFERENCES users (id),
        PRIMARY KEY (group_id, user_id)
    )""")
    op.execute("""
    CREATE TABLE group_app_access (
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        group_id uuid NOT NULL REFERENCES groups (id) ON DELETE CASCADE,
        application_id uuid NOT NULL REFERENCES applications (id),
        tier_id uuid NOT NULL REFERENCES tiers (id) ON DELETE RESTRICT,
        PRIMARY KEY (group_id, application_id)
    )""")
    op.execute("""
    CREATE TABLE tenant_app_licenses (
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        application_id uuid NOT NULL REFERENCES applications (id),
        tier_id uuid NOT NULL REFERENCES tiers (id) ON DELETE RESTRICT,
        seat_limit integer,
        expires_at timestamptz,
        PRIMARY KEY (tenant_id, application_id)
    )""")
    op.execute("""
    CREATE TABLE access_requests (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        user_id uuid NOT NULL REFERENCES users (id),
        application_id uuid NOT NULL REFERENCES applications (id),
        requested_tier text NOT NULL DEFAULT 'basic',
        note text NOT NULL DEFAULT '',
        status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'approved', 'rejected')),
        reviewed_by uuid REFERENCES users (id),
        created_at timestamptz NOT NULL DEFAULT now()
    )""")
    op.execute("""
    CREATE UNIQUE INDEX one_open_request ON access_requests (tenant_id, user_id, application_id)
    WHERE status = 'open'
    """)
    op.execute("""
    CREATE TABLE admin_roles (
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        user_id uuid NOT NULL REFERENCES users (id),
        role text NOT NULL CHECK (role IN ('super_admin', 'app_admin', 'helpdesk', 'auditor')),
        application_id uuid REFERENCES applications (id),
        PRIMARY KEY (tenant_id, user_id)
    )""")
    op.execute("""
    CREATE TABLE access_audit_log (
        id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        tenant_id uuid NOT NULL REFERENCES tenants (id),
        actor_id uuid,
        action text NOT NULL,
        target text NOT NULL DEFAULT '',
        before jsonb,
        after jsonb,
        reason text NOT NULL DEFAULT '',
        reference_id text NOT NULL DEFAULT '',
        at timestamptz NOT NULL DEFAULT now()
    )""")
    op.execute("CREATE INDEX audit_reference ON access_audit_log (reference_id)")

    op.execute("""
    CREATE FUNCTION app_tenant_id() RETURNS uuid
    LANGUAGE sql STABLE AS $$
        SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
    $$""")
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(f"""
        CREATE POLICY tenant_isolation ON {table}
            USING (tenant_id = app_tenant_id())
            WITH CHECK (tenant_id = app_tenant_id())
        """)

    op.execute("""
    GRANT SELECT, INSERT, UPDATE ON
        users, tenants, applications, application_clients, tiers, features,
        user_app_access, groups, tenant_app_licenses, access_requests
    TO access_app
    """)
    op.execute("""
    GRANT SELECT, INSERT, UPDATE, DELETE ON
        tier_features, group_members, group_app_access, admin_roles
    TO access_app
    """)
    op.execute("GRANT DELETE ON tiers, groups TO access_app")
    # The audit log is append-only for the service: no update, and no delete.
    op.execute("GRANT SELECT, INSERT ON access_audit_log TO access_app")


def downgrade() -> None:
    op.execute("""
    DROP TABLE access_audit_log, admin_roles, access_requests, tenant_app_licenses,
               group_app_access, group_members, groups, user_app_access, tier_features,
               features, tiers, application_clients, applications, users, tenants
    """)
    op.execute("DROP FUNCTION app_tenant_id()")
