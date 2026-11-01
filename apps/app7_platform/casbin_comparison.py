"""The same role rules, expressed in Casbin, to compare with our own database tables.

What this comparison shows:
- Casbin keeps rules in one policy format, and supports RBAC, ABAC, and more through a model file.
- Our tables are simpler for one app, and are protected by normal database transactions.
- A policy engine starts to pay off when many services must share the same rules.
"""

import tempfile
from collections.abc import Iterable
from pathlib import Path

import casbin

MODEL = """
[request_definition]
r = role, permission

[policy_definition]
p = role, permission

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.role == p.role && r.permission == p.permission
"""


def build_enforcer(rules: Iterable[tuple[str, str]]) -> casbin.Enforcer:
    with tempfile.TemporaryDirectory() as folder:
        model_path = Path(folder) / "model.conf"
        model_path.write_text(MODEL, encoding="utf-8")
        enforcer = casbin.Enforcer(str(model_path))
    for role, permission in rules:
        enforcer.add_policy(role, permission)
    return enforcer
