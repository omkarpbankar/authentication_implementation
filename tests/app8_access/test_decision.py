"""Every rule of the access decision, including the edge cases from the plan."""

from datetime import UTC, datetime, timedelta

import pytest

from apps.app8_access.access_service.decision import Facts, Grant, decide, effective_tier

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
HOUR = timedelta(hours=1)
TIERS = {10: "basic", 20: "standard", 30: "premium"}
FEATURES = {
    "basic": {"notes.read": None, "notes.create": 50},
    "standard": {"notes.read": None, "notes.create": None, "notes.share": None},
    "premium": {
        "notes.read": None,
        "notes.create": None,
        "notes.share": None,
        "notes.export": None,
    },
}
BASIC = Grant("basic", 10)
STANDARD = Grant("standard", 20)
PREMIUM = Grant("premium", 30)


def facts(*grants, **overrides):
    defaults = {"now": NOW, "grants": grants, "tiers": TIERS, "tier_features": FEATURES}
    return Facts(**{**defaults, **overrides})


def test_default_deny_with_no_grant():
    result = decide(facts())
    assert (result.allowed, result.reason_code) == (False, "NO_APP_ACCESS")


def test_grant_gives_access_at_its_tier():
    result = decide(facts(STANDARD))
    assert (result.allowed, result.tier) == (True, "standard")


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"user_status": "disabled"}, "USER_DISABLED"),
        ({"tenant_status": "suspended"}, "TENANT_SUSPENDED"),
        ({"app_status": "maintenance"}, "APP_MAINTENANCE"),
        ({"app_status": "retired"}, "APP_RETIRED"),
    ],
)
def test_blocks_apply_even_with_a_premium_grant(overrides, reason):
    assert decide(facts(PREMIUM, **overrides)).reason_code == reason


def test_disabled_user_is_checked_before_everything_else():
    result = decide(facts(user_status="disabled", tenant_status="suspended", app_status="retired"))
    assert result.reason_code == "USER_DISABLED"


def test_suspended_grant_is_denied():
    assert decide(facts(Grant("basic", 10, status="suspended"))).reason_code == "ACCESS_SUSPENDED"


def test_revoked_grant_counts_as_no_grant():
    assert decide(facts(Grant("basic", 10, status="revoked"))).reason_code == "NO_APP_ACCESS"


def test_grant_that_has_not_started_is_denied():
    grant = Grant("basic", 10, starts_at=NOW + HOUR)
    assert decide(facts(grant)).reason_code == "ACCESS_EXPIRED"


def test_grant_expiring_exactly_now_is_denied():
    assert decide(facts(Grant("basic", 10, expires_at=NOW))).reason_code == "ACCESS_EXPIRED"


def test_grant_expiring_one_second_later_is_allowed():
    grant = Grant("basic", 10, expires_at=NOW + timedelta(seconds=1))
    assert decide(facts(grant)).allowed


def test_grant_starting_exactly_now_is_allowed():
    assert decide(facts(Grant("basic", 10, starts_at=NOW))).allowed


def test_direct_basic_and_group_premium_gives_premium():
    result = decide(facts(BASIC, Grant("premium", 30, direct=False)))
    assert result.tier == "premium"


def test_leaving_the_group_falls_back_to_the_direct_grant():
    assert decide(facts(BASIC)).tier == "basic"


def test_suspended_direct_grant_beats_an_active_group_grant():
    result = decide(
        facts(Grant("basic", 10, status="suspended"), Grant("premium", 30, direct=False))
    )
    assert result.reason_code == "ACCESS_SUSPENDED"


def test_suspended_group_grant_does_not_block_a_direct_grant():
    result = decide(facts(BASIC, Grant("premium", 30, status="suspended", direct=False)))
    assert result.tier == "basic"


def test_expired_group_grant_falls_back_to_a_live_direct_grant():
    result = decide(facts(BASIC, Grant("premium", 30, expires_at=NOW - HOUR, direct=False)))
    assert result.tier == "basic"


def test_license_caps_the_tier():
    assert decide(facts(PREMIUM, license_rank=20)).tier == "standard"


def test_license_does_not_raise_a_lower_tier():
    assert decide(facts(BASIC, license_rank=30)).tier == "basic"


def test_license_below_every_tier_denies():
    assert decide(facts(BASIC, license_rank=5)).reason_code == "NO_APP_ACCESS"


def test_feature_included_in_the_tier_is_allowed():
    assert decide(facts(PREMIUM), feature="notes.export").allowed


def test_feature_above_the_tier_says_so():
    result = decide(facts(BASIC), feature="notes.export")
    assert (result.reason_code, result.tier) == ("TIER_TOO_LOW", "basic")


def test_capped_user_loses_the_capped_tiers_features():
    result = decide(facts(PREMIUM, license_rank=20), feature="notes.export")
    assert result.reason_code == "TIER_TOO_LOW"


def test_brand_new_feature_is_in_no_tier():
    assert decide(facts(PREMIUM), feature="notes.brand_new").reason_code == "TIER_TOO_LOW"


def test_quota_allows_use_below_the_limit():
    assert decide(facts(BASIC), feature="notes.create", usage=49).allowed


def test_quota_blocks_at_the_limit():
    result = decide(facts(BASIC), feature="notes.create", usage=50)
    assert result.reason_code == "QUOTA_EXCEEDED"


def test_unlimited_tier_ignores_usage():
    assert decide(facts(STANDARD), feature="notes.create", usage=999_999).allowed


def test_downgraded_user_over_the_limit_can_read_but_not_create():
    assert decide(facts(BASIC), feature="notes.read", usage=200).allowed
    assert decide(facts(BASIC), feature="notes.create", usage=200).reason_code == "QUOTA_EXCEEDED"


def test_new_tier_between_two_others_needs_no_grant_changes():
    tiers = {10: "basic", 15: "plus", 20: "standard", 30: "premium"}
    assert decide(facts(STANDARD, tiers=tiers)).tier == "standard"
    assert decide(facts(Grant("plus", 15), tiers=tiers, tier_features={"plus": {}})).tier == "plus"


def test_capping_uses_the_nearest_lower_tier():
    tiers = {10: "basic", 15: "plus", 20: "standard", 30: "premium"}
    result = effective_tier(facts(PREMIUM, license_rank=18, tiers=tiers))
    assert result.tier == "plus"
