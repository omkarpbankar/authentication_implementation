"""Direct proof that the database itself enforces tenant isolation.

These tests skip the application completely, and connect as the app's real database role, so
they show what happens when a query forgets its tenant filter.
"""

import asyncio
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine

from apps.app7_platform.database import set_context

from .conftest import APP_URL, OWNER_URL, run_sql

UNFILTERED = "SELECT title, tenant_id FROM documents"


@pytest.fixture
def two_tenants():
    tenants = []
    for name in ("a", "b"):
        slug = f"rls-{name}-{uuid.uuid4().hex[:8]}"
        tenant_id = run_sql(
            APP_URL,
            "INSERT INTO tenants (slug, name) VALUES (:s, :s) RETURNING id",
            {"s": slug},
        )[0]["id"]
        user_id = run_sql(APP_URL, "INSERT INTO users DEFAULT VALUES RETURNING id")[0]["id"]
        project_id = run_sql(
            APP_URL,
            "INSERT INTO projects (tenant_id, name) VALUES (:t, 'p') RETURNING id",
            {"t": tenant_id},
            tenant=tenant_id,
        )[0]["id"]
        run_sql(
            APP_URL,
            """INSERT INTO documents (tenant_id, project_id, owner_id, title)
               VALUES (:t, :p, :u, :title)""",
            {"t": tenant_id, "p": project_id, "u": user_id, "title": f"doc-{name}"},
            tenant=tenant_id,
        )
        tenants.append({"id": tenant_id, "project": project_id, "user": user_id})
    return tenants


def test_unfiltered_query_returns_only_the_current_tenant(two_tenants):
    a, _ = two_tenants
    rows = run_sql(APP_URL, UNFILTERED, tenant=a["id"])
    assert [row["title"] for row in rows] == ["doc-a"]


def test_no_tenant_set_returns_no_rows(two_tenants):
    assert run_sql(APP_URL, UNFILTERED) == []


def test_filtering_for_another_tenant_finds_nothing(two_tenants):
    a, b = two_tenants
    rows = run_sql(
        APP_URL, "SELECT * FROM documents WHERE tenant_id = :t", {"t": b["id"]}, tenant=a["id"]
    )
    assert rows == []


def test_table_owner_is_also_blocked(two_tenants):
    assert run_sql(OWNER_URL, UNFILTERED) == []


def test_cannot_insert_a_row_for_another_tenant(two_tenants):
    a, b = two_tenants
    with pytest.raises(DBAPIError, match="row-level security"):
        run_sql(
            APP_URL,
            "INSERT INTO projects (tenant_id, name) VALUES (:t, 'x')",
            {"t": b["id"]},
            tenant=a["id"],
        )


def test_cannot_move_a_row_to_another_tenant(two_tenants):
    a, b = two_tenants
    with pytest.raises(DBAPIError, match="row-level security"):
        run_sql(
            APP_URL,
            "UPDATE projects SET tenant_id = :t WHERE name = 'p'",
            {"t": b["id"]},
            tenant=a["id"],
        )


def test_cannot_update_or_delete_another_tenants_rows(two_tenants):
    a, b = two_tenants
    run_sql(APP_URL, "UPDATE documents SET title = 'hacked'", tenant=a["id"])
    run_sql(APP_URL, "DELETE FROM documents WHERE title = 'doc-b'", tenant=a["id"])
    rows = run_sql(APP_URL, UNFILTERED, tenant=b["id"])
    assert [row["title"] for row in rows] == ["doc-b"]


def test_composite_key_blocks_pointing_at_another_tenants_project(two_tenants):
    a, b = two_tenants
    with pytest.raises(DBAPIError, match="foreign key"):
        run_sql(
            APP_URL,
            """INSERT INTO documents (tenant_id, project_id, owner_id, title)
               VALUES (:t, :p, :u, 'sneaky')""",
            {"t": a["id"], "p": b["project"], "u": a["user"]},
            tenant=a["id"],
        )


def test_two_tenants_can_use_the_same_project_name(two_tenants):
    a, b = two_tenants
    for tenant in (a, b):
        rows = run_sql(APP_URL, "SELECT name FROM projects", tenant=tenant["id"])
        assert [row["name"] for row in rows] == ["p"]


def test_audit_log_is_append_only_for_the_app(two_tenants):
    a, _ = two_tenants
    run_sql(
        APP_URL,
        "INSERT INTO audit_log (tenant_id, action) VALUES (:t, 'x')",
        {"t": a["id"]},
        tenant=a["id"],
    )
    for statement in ("UPDATE audit_log SET action = 'y'", "DELETE FROM audit_log"):
        with pytest.raises(DBAPIError, match="permission denied"):
            run_sql(APP_URL, statement, tenant=a["id"])


def test_app_role_cannot_bypass_row_level_security():
    roles = run_sql(
        OWNER_URL,
        "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = 'platform_app'",
    )
    assert roles == [{"rolsuper": False, "rolbypassrls": False}]


def test_app_role_owns_no_tables():
    owned = run_sql(OWNER_URL, "SELECT tablename FROM pg_tables WHERE tableowner = 'platform_app'")
    assert owned == []


def test_every_table_with_a_tenant_id_has_forced_rls():
    """Fails if a future migration adds a tenant table and forgets its policy."""
    missing = run_sql(
        OWNER_URL,
        """
        SELECT c.relname FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped
        WHERE n.nspname = 'public' AND c.relkind = 'r'
          AND c.relname NOT IN ('tenant_idp_connections', 'tenant_domains')
          AND NOT (c.relrowsecurity AND c.relforcerowsecurity)
        """,
    )
    assert missing == []


def test_tenant_setting_does_not_leak_between_pooled_transactions(two_tenants):
    a, _ = two_tenants

    async def go():
        engine = create_async_engine(APP_URL, pool_size=1, max_overflow=0)
        async with engine.begin() as connection:
            await set_context(connection, a["id"])
            assert len((await connection.execute(text(UNFILTERED))).all()) == 1
        # The same physical connection comes back from the pool, with no tenant set.
        async with engine.begin() as connection:
            assert (await connection.execute(text(UNFILTERED))).all() == []
        await engine.dispose()

    asyncio.run(go())


def test_concurrent_requests_never_see_each_others_data(two_tenants):
    """Two tenants share a small pool under load, as they would in production."""

    async def visit(engine, tenant, expected):
        for _ in range(25):
            async with engine.begin() as connection:
                await set_context(connection, tenant["id"])
                titles = {row[0] for row in await connection.execute(text(UNFILTERED))}
                assert titles == {expected}

    async def go():
        engine = create_async_engine(APP_URL, pool_size=3, max_overflow=0)
        a, b = two_tenants
        await asyncio.gather(
            *(visit(engine, a, "doc-a") for _ in range(8)),
            *(visit(engine, b, "doc-b") for _ in range(8)),
        )
        await engine.dispose()

    asyncio.run(go())
