"""Acts like a person's browser on Keycloak's pages, for live checks.

It signs in with the public practice accounts, on the local server only.
"""

import html
import re
from urllib.parse import urljoin

import httpx

PASSWORD = "correct-horse-battery"


def form_action(page: str) -> str:
    match = re.search(r'<form[^>]*action="([^"]+)"', page)
    if match is None:
        raise RuntimeError("No form found on the page")
    return html.unescape(match.group(1))


def sign_in(client: httpx.Client, login_page: httpx.Response, username: str) -> httpx.Response:
    """Submit Keycloak's login form, then follow redirects back to the app.

    With organizations enabled, Keycloak asks for the username first and the password on a
    second page, which is known as identity-first login.
    """
    response = client.post(
        urljoin(str(login_page.url), form_action(login_page.text)),
        data={"username": username, "password": PASSWORD, "credentialId": ""},
        follow_redirects=True,
    )
    if 'name="password"' in response.text and "realms/course" in str(response.url):
        response = client.post(
            urljoin(str(response.url), form_action(response.text)),
            data={"username": username, "password": PASSWORD, "credentialId": ""},
            follow_redirects=True,
        )
    return response


def accept_consent(client: httpx.Client, page: httpx.Response) -> httpx.Response | None:
    """Click Yes on Keycloak's Grant Access page, if the page is showing one."""
    code = re.search(r'name="code" value="([^"]+)"', page.text)
    if code is None:
        return None
    return client.post(
        urljoin(str(page.url), form_action(page.text)),
        data={"code": code.group(1), "accept": "Yes"},
    )


def browser() -> httpx.Client:
    # Real browsers send Secure cookies to localhost, but Python's cookie jar will not.
    def allow_secure_cookies_on_localhost(response: httpx.Response) -> None:
        for cookie in client.cookies.jar:
            cookie.secure = False

    client = httpx.Client(
        follow_redirects=True,
        timeout=15,
        event_hooks={"response": [allow_secure_cookies_on_localhost]},
    )
    return client
