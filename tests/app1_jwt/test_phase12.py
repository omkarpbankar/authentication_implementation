"""Rate limits, session management, and emergency key rotation."""

from apps.app1_jwt.keys import KeyRing

from .conftest import EMAIL, PASSWORD, bearer


def wrong_login(client, email=EMAIL):
    return client.post("/auth/login", data={"username": email, "password": "wrong-password"})


def test_repeated_guessing_is_slowed_down(client, tokens):
    codes = [wrong_login(client).status_code for _ in range(12)]
    assert codes[0] == 401
    assert codes[-1] == 429


def test_rate_limit_response_says_when_to_retry(client, tokens):
    for _ in range(11):
        response = wrong_login(client)
    assert response.headers["retry-after"] == "60"


def test_guessing_at_one_account_does_not_block_another(client, tokens):
    for _ in range(12):
        wrong_login(client)
    other = wrong_login(client, "someone-else@example.com")
    assert other.status_code == 401


def test_user_can_see_their_sessions(client, tokens):
    second = client.post("/auth/login", data={"username": EMAIL, "password": PASSWORD}).json()
    sessions = client.get("/sessions", headers=bearer(second["access_token"])).json()
    assert len(sessions) == 2
    assert sum(session["current"] for session in sessions) == 1


def test_ending_a_session_stops_that_device_only(client, tokens):
    second = client.post("/auth/login", data={"username": EMAIL, "password": PASSWORD}).json()
    headers = bearer(second["access_token"])
    other = next(s for s in client.get("/sessions", headers=headers).json() if not s["current"])

    assert client.delete(f"/sessions/{other['id']}", headers=headers).status_code == 204

    assert client.get("/users/me", headers=bearer(tokens["access_token"])).status_code == 401
    refresh = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh.status_code == 401
    assert client.get("/users/me", headers=headers).status_code == 200


def test_cannot_end_another_users_session(client, tokens):
    client.post("/auth/register", json={"email": "b@example.com", "password": PASSWORD})
    other = client.post(
        "/auth/login", data={"username": "b@example.com", "password": PASSWORD}
    ).json()
    mine = client.get("/sessions", headers=bearer(tokens["access_token"])).json()[0]["id"]
    response = client.delete(f"/sessions/{mine}", headers=bearer(other["access_token"]))
    assert response.status_code == 404


def test_retiring_a_key_on_disk_reaches_a_running_process(client, tokens, ring):
    """The emergency path: another process removes the key while the API keeps running."""
    headers = bearer(tokens["access_token"])
    assert client.get("/users/me", headers=headers).status_code == 200

    other_process = KeyRing.load_or_create(ring.directory)
    old_kid = other_process.active_kid
    other_process.rotate()
    other_process.retire(old_kid)

    assert client.get("/users/me", headers=headers).status_code == 401
