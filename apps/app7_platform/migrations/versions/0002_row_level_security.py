"""Row-level security: the database enforces tenant isolation, even if app code forgets."""

from alembic import op

revision = "0002"
down_revision = "0001"

TENANT_TABLES = ["memberships", "projects", "documents", "audit_log", "support_grants"]


def upgrade() -> None:
    # NULLIF matters. After a transaction ends, the setting reads as '' rather than NULL, and
    # casting '' to uuid raises an error. With NULLIF, no tenant simply matches no rows.
    op.execute("""
    CREATE FUNCTION app_tenant_id() RETURNS uuid
    LANGUAGE sql STABLE AS $$
        SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
    $$""")
    op.execute("""
    CREATE FUNCTION app_user_id() RETURNS uuid
    LANGUAGE sql STABLE AS $$
        SELECT NULLIF(current_setting('app.user_id', true), '')::uuid
    $$""")

    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        # FORCE applies the policies to the table owner too.
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        # USING filters what can be read. WITH CHECK validates what gets written.
        op.execute(f"""
        CREATE POLICY tenant_isolation ON {table}
            USING (tenant_id = app_tenant_id())
            WITH CHECK (tenant_id = app_tenant_id())
        """)

    # Users may see their own memberships before choosing a tenant.
    op.execute("""
    CREATE POLICY own_memberships ON memberships FOR SELECT
        USING (user_id = app_user_id())
    """)

    # Support can read a tenant only while a grant is live, and is otherwise blocked.
    for table in ("projects", "documents"):
        op.execute(f"""
        CREATE POLICY support_read ON {table} FOR SELECT TO platform_support
            USING (EXISTS (
                SELECT 1 FROM support_grants g
                WHERE g.tenant_id = {table}.tenant_id
                  AND g.support_user_id = app_user_id()
                  AND g.expires_at > now()
            ))
        """)
    op.execute("""
    CREATE POLICY support_own_grants ON support_grants FOR SELECT TO platform_support
        USING (support_user_id = app_user_id())
    """)
    op.execute("""
    CREATE POLICY support_audit ON audit_log FOR INSERT TO platform_support
        WITH CHECK (actor_id = app_user_id())
    """)


def downgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
        op.execute(f"DROP POLICY tenant_isolation ON {table}")
    op.execute("DROP POLICY own_memberships ON memberships")
    op.execute("DROP POLICY support_read ON projects")
    op.execute("DROP POLICY support_read ON documents")
    op.execute("DROP POLICY support_own_grants ON support_grants")
    op.execute("DROP POLICY support_audit ON audit_log")
    op.execute("DROP FUNCTION app_tenant_id()")
    op.execute("DROP FUNCTION app_user_id()")
