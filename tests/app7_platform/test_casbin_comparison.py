from apps.app7_platform.casbin_comparison import build_enforcer

from .conftest import OWNER_URL, run_sql


def test_casbin_reaches_the_same_decision_as_our_tables():
    rows = run_sql(OWNER_URL, "SELECT role, permission FROM role_permissions")
    rules = {(row["role"], row["permission"]) for row in rows}
    roles = {role for role, _ in rules}
    permissions = {permission for _, permission in rules}
    enforcer = build_enforcer(rules)

    for role in roles:
        for permission in permissions:
            assert enforcer.enforce(role, permission) == ((role, permission) in rules)


def test_casbin_denies_by_default():
    assert not build_enforcer([("viewer", "document:read")]).enforce("viewer", "org:manage")
