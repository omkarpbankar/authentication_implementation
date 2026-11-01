"""What users see for each decision. Reason codes stay stable, and wording can change."""

NOT_AUTHORIZED = "You are not authorized to use this application. Please check with your admin."

# reason code: (HTTP status, message)
REASONS = {
    "USER_DISABLED": (403, "Your account is disabled. Please contact your admin."),
    "TENANT_SUSPENDED": (403, "Your organization's access is suspended."),
    "APP_MAINTENANCE": (503, "This application is temporarily unavailable."),
    "APP_RETIRED": (410, "This application is no longer available."),
    "NO_APP_ACCESS": (403, NOT_AUTHORIZED),
    "ACCESS_SUSPENDED": (403, "Your access is suspended. Please check with your admin."),
    "ACCESS_EXPIRED": (403, "Your access has expired. Please check with your admin."),
    "TIER_TOO_LOW": (
        403,
        "This feature is not included in your {tier} plan. Please check with your admin.",
    ),
    "QUOTA_EXCEEDED": (403, "You have reached your {tier} plan limit."),
}

# Only these can be helped by asking an admin for access.
REQUESTABLE = {"NO_APP_ACCESS", "ACCESS_EXPIRED", "TIER_TOO_LOW", "QUOTA_EXCEEDED"}


def describe(reason_code: str, tier: str = "") -> tuple[int, str]:
    status, message = REASONS.get(reason_code, REASONS["NO_APP_ACCESS"])
    return status, message.format(tier=(tier or "current").title())
