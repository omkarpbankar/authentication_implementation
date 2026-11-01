"""Every SQL statement App 7 runs, in one place."""

from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from apps.app7_platform.identity import Identity


def rows(result) -> list[dict]:
    return [dict(row) for row in result.mappings().all()]


def first(result) -> dict | None:
    row = result.mappings().first()
    return dict(row) if row else None


async def tenant_by_slug(db: AsyncConnection, slug: str) -> dict | None:
    return first(await db.execute(text("SELECT * FROM tenants WHERE slug = :s"), {"s": slug}))


async def tenant_by_id(db: AsyncConnection, tenant_id: UUID) -> dict | None:
    return first(await db.execute(text("SELECT * FROM tenants WHERE id = :i"), {"i": tenant_id}))


async def find_or_create_user(db: AsyncConnection, identity: Identity) -> UUID:
    """Create the user the first time this provider login is seen."""
    existing = first(
        await db.execute(
            text("SELECT user_id FROM user_identities WHERE issuer = :i AND subject = :s"),
            {"i": identity.issuer, "s": identity.subject},
        )
    )
    if existing:
        return existing["user_id"]
    user = first(
        await db.execute(
            text("INSERT INTO users (email, name) VALUES (:e, :n) RETURNING id"),
            {"e": identity.email, "n": identity.name},
        )
    )
    await db.execute(
        text("INSERT INTO user_identities VALUES (:i, :s, :u) ON CONFLICT DO NOTHING"),
        {"i": identity.issuer, "s": identity.subject, "u": user["id"]},
    )
    return user["id"]


async def tenant_for_connection(db: AsyncConnection, identity: Identity) -> UUID | None:
    if not identity.external_tenant:
        return None
    row = first(
        await db.execute(
            text(
                "SELECT tenant_id FROM tenant_idp_connections"
                " WHERE issuer = :i AND external_tenant_id = :e"
            ),
            {"i": identity.issuer, "e": identity.external_tenant},
        )
    )
    return row["tenant_id"] if row else None


async def memberships_of(db: AsyncConnection) -> list[dict]:
    """Relies on the own_memberships policy, so it needs app.user_id to be set."""
    return rows(
        await db.execute(
            text("""
            SELECT t.id AS tenant_id, t.slug, t.name, t.status, m.role
            FROM memberships m JOIN tenants t ON t.id = m.tenant_id
            ORDER BY t.slug
            """)
        )
    )


async def membership(db: AsyncConnection, tenant_id: UUID, user_id: UUID) -> dict | None:
    return first(
        await db.execute(
            text("""
            SELECT m.user_id, m.role, m.clearance, r.rank,
                   COALESCE(array_agg(p.permission) FILTER (WHERE p.permission IS NOT NULL), '{}')
                       AS permissions
            FROM memberships m
            JOIN roles r ON r.name = m.role
            LEFT JOIN role_permissions p ON p.role = m.role
            WHERE m.tenant_id = :t AND m.user_id = :u
            GROUP BY m.user_id, m.role, m.clearance, r.rank
            """),
            {"t": tenant_id, "u": user_id},
        )
    )


async def add_membership(
    db: AsyncConnection, tenant_id: UUID, user_id: UUID, role: str, clearance: int = 0
) -> None:
    await db.execute(
        text("""
        INSERT INTO memberships (tenant_id, user_id, role, clearance)
        VALUES (:t, :u, :r, :c) ON CONFLICT DO NOTHING
        """),
        {"t": tenant_id, "u": user_id, "r": role, "c": clearance},
    )


async def role_rank(db: AsyncConnection, role: str) -> int | None:
    row = first(await db.execute(text("SELECT rank FROM roles WHERE name = :r"), {"r": role}))
    return row["rank"] if row else None


async def list_members(db: AsyncConnection) -> list[dict]:
    return rows(
        await db.execute(
            text("""
            SELECT m.user_id, u.email, u.name, m.role, m.clearance
            FROM memberships m JOIN users u ON u.id = m.user_id
            WHERE m.tenant_id = app_tenant_id()
            ORDER BY u.email
            """)
        )
    )


async def set_role(db: AsyncConnection, user_id: UUID, role: str) -> None:
    await db.execute(
        text("UPDATE memberships SET role = :r WHERE user_id = :u AND tenant_id = app_tenant_id()"),
        {"r": role, "u": user_id},
    )


async def remove_member(db: AsyncConnection, user_id: UUID) -> None:
    await db.execute(
        text("DELETE FROM memberships WHERE user_id = :u AND tenant_id = app_tenant_id()"),
        {"u": user_id},
    )


async def owner_count(db: AsyncConnection) -> int:
    row = first(
        await db.execute(
            text(
                "SELECT count(*) AS total FROM memberships"
                " WHERE role = 'owner' AND tenant_id = app_tenant_id()"
            )
        )
    )
    return row["total"]


async def create_project(db: AsyncConnection, tenant_id: UUID, name: str) -> dict:
    return first(
        await db.execute(
            text("INSERT INTO projects (tenant_id, name) VALUES (:t, :n) RETURNING id, name"),
            {"t": tenant_id, "n": name},
        )
    )


async def list_projects(db: AsyncConnection) -> list[dict]:
    return rows(await db.execute(text("SELECT id, name FROM projects ORDER BY name")))


async def create_document(
    db: AsyncConnection,
    tenant_id: UUID,
    project_id: UUID,
    owner_id: UUID,
    title: str,
    body: str,
    confidential: bool,
) -> dict:
    return first(
        await db.execute(
            text("""
            INSERT INTO documents (tenant_id, project_id, owner_id, title, body, confidential)
            VALUES (:t, :p, :o, :title, :body, :c)
            RETURNING id, project_id, owner_id, title, body, confidential
            """),
            {
                "t": tenant_id,
                "p": project_id,
                "o": owner_id,
                "title": title,
                "body": body,
                "c": confidential,
            },
        )
    )


async def document(db: AsyncConnection, document_id: UUID) -> dict | None:
    return first(
        await db.execute(
            text("""
            SELECT id, project_id, owner_id, title, body, confidential
            FROM documents WHERE id = :d
            """),
            {"d": document_id},
        )
    )


async def list_documents(db: AsyncConnection, clearance: int) -> list[dict]:
    return rows(
        await db.execute(
            text("""
            SELECT id, project_id, owner_id, title, confidential FROM documents
            WHERE NOT confidential OR :c >= 1
            ORDER BY title
            """),
            {"c": clearance},
        )
    )


async def update_document(db: AsyncConnection, document_id: UUID, title: str, body: str) -> None:
    await db.execute(
        text("UPDATE documents SET title = :t, body = :b WHERE id = :d"),
        {"t": title, "b": body, "d": document_id},
    )


async def delete_document(db: AsyncConnection, document_id: UUID) -> None:
    await db.execute(text("DELETE FROM documents WHERE id = :d"), {"d": document_id})


async def audit(
    db: AsyncConnection, tenant_id: UUID, actor_id: UUID, action: str, target: str = ""
) -> None:
    await db.execute(
        text("INSERT INTO audit_log (tenant_id, actor_id, action, target) VALUES (:t, :a, :x, :o)"),
        {"t": tenant_id, "a": actor_id, "x": action, "o": target},
    )


async def audit_entries(db: AsyncConnection) -> list[dict]:
    return rows(
        await db.execute(
            text("SELECT actor_id, action, target, at FROM audit_log ORDER BY id DESC LIMIT 100")
        )
    )


async def discover_domain(db: AsyncConnection, domain: str) -> dict | None:
    return first(
        await db.execute(
            text("""
            SELECT t.slug, d.sso_enforced
            FROM tenant_domains d JOIN tenants t ON t.id = d.tenant_id
            WHERE d.domain = :d AND d.verified
            """),
            {"d": domain},
        )
    )


async def set_tenant_status(db: AsyncConnection, tenant_id: UUID, status: str) -> None:
    await db.execute(
        text("UPDATE tenants SET status = :s WHERE id = :t"), {"s": status, "t": tenant_id}
    )


async def delete_tenant(db: AsyncConnection, tenant_id: UUID) -> None:
    await db.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": tenant_id})
