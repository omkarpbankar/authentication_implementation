"""Roles and permissions, stored as data so they can change without a code change."""

from alembic import op

revision = "0003"
down_revision = "0002"

VIEWER = ["document:read", "document:write_own", "project:read", "member:read"]
EDITOR = [*VIEWER, "document:write", "project:write"]
ADMIN = [*EDITOR, "document:delete", "member:manage", "audit:read"]
OWNER = [*ADMIN, "org:manage"]
ROLES = {"viewer": (10, VIEWER), "editor": (20, EDITOR), "admin": (30, ADMIN), "owner": (40, OWNER)}


def upgrade() -> None:
    # Rank is what stops someone from granting a role above their own.
    op.execute("CREATE TABLE roles (name text PRIMARY KEY, rank integer NOT NULL UNIQUE)")
    op.execute("""
    CREATE TABLE role_permissions (
        role text NOT NULL REFERENCES roles (name) ON DELETE CASCADE,
        permission text NOT NULL,
        PRIMARY KEY (role, permission)
    )""")
    for name, (rank, permissions) in ROLES.items():
        op.execute(f"INSERT INTO roles VALUES ('{name}', {rank})")
        for permission in permissions:
            op.execute(f"INSERT INTO role_permissions VALUES ('{name}', '{permission}')")
    op.execute("""
    ALTER TABLE memberships
        ADD CONSTRAINT memberships_role FOREIGN KEY (role) REFERENCES roles (name)
    """)
    op.execute("GRANT SELECT ON roles, role_permissions TO platform_app")


def downgrade() -> None:
    op.execute("ALTER TABLE memberships DROP CONSTRAINT memberships_role")
    op.execute("DROP TABLE role_permissions, roles")
