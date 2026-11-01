"""The access decision. Pure logic with no database, so every rule is easy to test.

Checks run in a fixed order, and the first failure decides the result. Default deny: reaching
the end with no valid grant means no access.
"""

from dataclasses import dataclass, field
from datetime import datetime

NOT_AUTHORIZED = "NO_APP_ACCESS"


@dataclass(frozen=True)
class Grant:
    tier_key: str
    tier_rank: int
    status: str = "active"  # active, suspended, or revoked
    starts_at: datetime | None = None
    expires_at: datetime | None = None
    direct: bool = True


@dataclass(frozen=True)
class Facts:
    now: datetime
    user_status: str = "active"
    tenant_status: str = "active"
    app_status: str = "active"
    grants: tuple[Grant, ...] = ()
    # The highest tier this tenant's license allows, if there is a license.
    license_rank: int | None = None
    # Every tier for this application, by rank, used for capping.
    tiers: dict[int, str] = field(default_factory=dict)
    # Features of each tier: {tier_key: {feature_key: limit or None}}.
    tier_features: dict[str, dict[str, int | None]] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason_code: str = ""
    tier: str = ""
    features: dict[str, int | None] = field(default_factory=dict)


def deny(reason_code: str, tier: str = "") -> Decision:
    return Decision(False, reason_code, tier)


def is_live(grant: Grant, now: datetime) -> bool:
    if grant.status != "active":
        return False
    if grant.starts_at and now < grant.starts_at:
        return False
    # At the exact expiry moment, access has ended.
    return not (grant.expires_at and now >= grant.expires_at)


def apply_license(rank: int, facts: Facts) -> int:
    """A tier cannot exceed the tenant's license, though the original grant stays on record."""
    if facts.license_rank is None or rank <= facts.license_rank:
        return rank
    allowed = [tier_rank for tier_rank in facts.tiers if tier_rank <= facts.license_rank]
    return max(allowed) if allowed else 0


def effective_tier(facts: Facts) -> Decision:
    grants = [grant for grant in facts.grants if grant.status != "revoked"]
    # A suspended direct grant wins, even if a group would otherwise give access.
    if any(grant.direct and grant.status == "suspended" for grant in grants):
        return deny("ACCESS_SUSPENDED")

    live = [grant for grant in grants if is_live(grant, facts.now)]
    if not live:
        return deny("ACCESS_EXPIRED" if grants else NOT_AUTHORIZED)

    rank = apply_license(max(grant.tier_rank for grant in live), facts)
    if rank == 0:
        return deny(NOT_AUTHORIZED)
    tier = facts.tiers.get(rank) or max(live, key=lambda grant: grant.tier_rank).tier_key
    return Decision(True, tier=tier, features=facts.tier_features.get(tier, {}))


def decide(facts: Facts, feature: str = "", usage: int | None = None) -> Decision:
    if facts.user_status != "active":
        return deny("USER_DISABLED")
    if facts.tenant_status != "active":
        return deny("TENANT_SUSPENDED")
    if facts.app_status == "maintenance":
        return deny("APP_MAINTENANCE")
    if facts.app_status != "active":
        return deny("APP_RETIRED")

    access = effective_tier(facts)
    if not access.allowed or not feature:
        return access

    # New features are in no tier until an admin adds them, so they are denied by default.
    if feature not in access.features:
        return deny("TIER_TOO_LOW", access.tier)

    limit = access.features[feature]
    if limit is not None and usage is not None and usage >= limit:
        return deny("QUOTA_EXCEEDED", access.tier)
    return access
