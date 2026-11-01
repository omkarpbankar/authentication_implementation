"""Generate keycloak/course-realm.json, the local login server's setup.

Everything here is a public practice value for local development only.
Run:  uv run python scripts/build_realm.py
"""

import json
from pathlib import Path

OUTPUT = Path(__file__).resolve().parent.parent / "keycloak" / "course-realm.json"
PASSWORD = "correct-horse-battery"
ADMIN_TOTP_SECRET = "course-admin-practice-totp-secret"


def audience_mapper(audience: str) -> dict:
    # Keycloak leaves your API out of "aud" unless you ask for it with a mapper like this.
    return {
        "name": f"audience-{audience}",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-audience-mapper",
        "config": {
            "included.custom.audience": audience,
            "access.token.claim": "true",
            "id.token.claim": "false",
        },
    }


def web_client(client_id: str, ports: list[int], audiences: list[str]) -> dict:
    origins = [f"http://localhost:{port}" for port in ports]
    return {
        "clientId": client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "secret": f"{client_id}-dev-secret",
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": False,
        "redirectUris": [f"{origin}/*" for origin in origins],
        "webOrigins": origins,
        "attributes": {
            "pkce.code.challenge.method": "S256",
            "post.logout.redirect.uris": "##".join(f"{origin}/*" for origin in origins),
        },
        "protocolMappers": [audience_mapper(audience) for audience in audiences],
    }


def service_client(client_id: str, audiences: list[str]) -> dict:
    return {
        "clientId": client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "secret": f"{client_id}-dev-secret",
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True,
        "protocolMappers": [audience_mapper(audience) for audience in audiences],
    }


def device_client(client_id: str, audiences: list[str]) -> dict:
    return {
        "clientId": client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": True,
        "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "attributes": {"oauth2.device.authorization.grant.enabled": "true"},
        "protocolMappers": [audience_mapper(audience) for audience in audiences],
    }


def tester_client(client_id: str, audiences: list[str]) -> dict:
    """Password grant, for live checks only. Real apps must never use this legacy flow."""
    return {
        **service_client(client_id, audiences),
        "serviceAccountsEnabled": False,
        "directAccessGrantsEnabled": True,
        "defaultClientScopes": ["basic", "profile", "email", "roles"],
        "optionalClientScopes": ["organization"],
    }


def organization(name: str, alias: str, domain: str, members: list[str]) -> dict:
    return {
        "name": name,
        "alias": alias,
        "enabled": True,
        "domains": [{"name": domain, "verified": True}],
        "members": [{"username": member, "membershipType": "MANAGED"} for member in members],
    }


def access_app_client(client_id: str, port: int) -> dict:
    """A web app that can also sign in as itself, to call the Access Service."""
    client = web_client(client_id, [port], [client_id, "access-service"])
    return {
        **client,
        "serviceAccountsEnabled": True,
        "defaultClientScopes": ["basic", "profile", "email", "roles"],
        "optionalClientScopes": ["organization"],
    }


def amr_mapper() -> dict:
    # Lists how the user signed in, so the admin panel can insist on a second factor.
    return {
        "name": "amr",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-amr-mapper",
        "config": {"access.token.claim": "true", "id.token.claim": "true"},
    }


def admin_panel_client() -> dict:
    client = access_app_client("admin-panel", 8011)
    return {**client, "protocolMappers": [*client["protocolMappers"], amr_mapper()]}


def saml_client() -> dict:
    base = "http://localhost:8007"
    return {
        "clientId": f"{base}/saml/metadata",
        "name": "app6-saml",
        "enabled": True,
        "protocol": "saml",
        # Leaves out the built-in role_list scope, which repeats its attribute name once per
        # role. The "roles" mapper below sends them all in one attribute instead.
        "defaultClientScopes": ["saml_organization"],
        "redirectUris": [f"{base}/*"],
        "frontchannelLogout": True,
        "attributes": {
            "saml.assertion.signature": "true",
            "saml.server.signature": "true",
            "saml.signature.algorithm": "RSA_SHA256",
            "saml.client.signature": "false",
            "saml.authnstatement": "true",
            "saml_name_id_format": "persistent",
            "saml_force_name_id_format": "true",
            "saml_assertion_consumer_url_post": f"{base}/saml/acs",
            "saml_single_logout_service_url_redirect": f"{base}/saml/sls",
        },
        "protocolMappers": [
            {
                "name": "email",
                "protocol": "saml",
                "protocolMapper": "saml-user-property-mapper",
                "config": {
                    "user.attribute": "email",
                    "attribute.name": "email",
                    "attribute.nameformat": "Basic",
                },
            },
            {
                "name": "roles",
                "protocol": "saml",
                "protocolMapper": "saml-role-list-mapper",
                "config": {
                    # One attribute with many values. The default repeats the attribute
                    # name, which strict SAML libraries reject as suspicious.
                    "single": "true",
                    "attribute.name": "roles",
                    "attribute.nameformat": "Basic",
                },
            },
        ],
    }


def admin_user(username: str, email: str) -> dict:
    """A practice admin with a TOTP code already set up, using a public practice secret."""
    otp = {
        "type": "otp",
        "userLabel": "practice",
        "secretData": json.dumps({"value": ADMIN_TOTP_SECRET}),
        "credentialData": json.dumps(
            {
                "subType": "totp",
                "digits": 6,
                "counter": 0,
                "period": 30,
                "algorithm": "HmacSHA1",
            }
        ),
    }
    person = user(username, email, [])
    return {**person, "credentials": [*person["credentials"], otp]}


def user(username: str, email: str, roles: list[str]) -> dict:
    return {
        "username": username,
        "email": email,
        "emailVerified": True,
        "firstName": username.title(),
        "lastName": "Tester",
        "enabled": True,
        "realmRoles": ["default-roles-course", *roles],
        "credentials": [{"type": "password", "value": PASSWORD, "temporary": False}],
    }


def build_realm() -> dict:
    return {
        "realm": "course",
        "enabled": True,
        "displayName": "Authentication Course",
        "sslRequired": "none",
        "registrationAllowed": False,
        "accessTokenLifespan": 300,
        "oauth2DeviceCodeLifespan": 600,
        "oauth2DevicePollingInterval": 1,
        "roles": {
            "realm": [
                {"name": "reader"},
                {"name": "writer"},
                {"name": "default-roles-course", "composite": False},
            ]
        },
        "clients": [
            web_client("app2-web", [8002, 8012], ["app2-api"]),
            service_client("app2-worker", ["app2-api"]),
            device_client("app2-cli", ["app2-api"]),
            web_client("app5-social", [8005], []),
            {
                **web_client("app6-oidc", [8006], []),
                "frontchannelLogout": False,
                "attributes": {
                    **web_client("app6-oidc", [8006], [])["attributes"],
                    # host.docker.internal is how a container reaches a server on your PC.
                    "backchannel.logout.url": "http://host.docker.internal:8006/backchannel-logout",
                    "backchannel.logout.session.required": "true",
                },
            },
            saml_client(),
            tester_client("app7-tester", ["app7-platform"]),
            access_app_client("notes-app", 8012),
            access_app_client("reports-app", 8013),
            access_app_client("files-app", 8014),
            admin_panel_client(),
        ],
        "organizationsEnabled": True,
        "organizations": [
            organization("Acme", "acme", "acme.example", ["asha", "meera", "neel", "vik"]),
            organization("Globex", "globex", "globex.example", ["ravi"]),
        ],
        "users": [
            user("asha", "asha@acme.example", ["reader", "writer"]),
            user("ravi", "ravi@globex.example", ["reader"]),
            # Super Admin, in Phase 11.
            admin_user("meera", "meera@acme.example"),
            # An ordinary user in Phase 11, who starts with no access.
            user("vik", "vik@acme.example", []),
            # An admin who has not set up a second factor, so the panel refuses them.
            user("neel", "neel@acme.example", []),
            # Has an unverified email, for testing that it can never claim an account.
            {**user("neha", "asha@acme.example.unverified", []), "emailVerified": False},
        ],
    }


if __name__ == "__main__":
    OUTPUT.parent.mkdir(exist_ok=True)
    OUTPUT.write_text(json.dumps(build_realm(), indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT.name}")
