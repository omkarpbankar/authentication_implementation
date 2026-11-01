"""Cognito calls this just before creating tokens, so it can add a custom claim.

Runs in AWS Lambda using the Pre Token Generation V2 event format.
"""


def handler(event, context):
    groups = event["request"]["groupConfiguration"].get("groupsToOverride") or []
    plan = "premium" if "admin" in groups else "basic"

    event["response"] = {
        "claimsAndScopeOverrideDetails": {
            "idTokenGeneration": {"claimsToAddOrOverride": {"plan": plan}},
            "accessTokenGeneration": {"claimsToAddOrOverride": {"plan": plan}},
        }
    }
    return event
