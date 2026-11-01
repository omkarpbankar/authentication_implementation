from .conftest import EMAIL, PASSWORD, bearer


def test_login_then_me(client, tokens):
    response = client.get("/users/me", headers=bearer(tokens["access_token"]))
    assert response.status_code == 200
    assert response.json()["email"] == EMAIL


def test_duplicate_registration_looks_like_a_new_one(client):
    body = {"email": EMAIL, "password": PASSWORD}
    first = client.post("/auth/register", json=body)
    second = client.post("/auth/register", json=body)
    assert first.status_code == second.status_code == 202
    assert first.json() == second.json()


def test_short_password_is_rejected(client):
    assert (
        client.post("/auth/register", json={"email": EMAIL, "password": "short"}).status_code == 422
    )


def test_wrong_password_and_unknown_email_look_identical(client, tokens):
    wrong = client.post("/auth/login", data={"username": EMAIL, "password": "wrong-password"})
    unknown = client.post("/auth/login", data={"username": "x@example.com", "password": "wrong"})
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_refresh_returns_a_new_working_pair(client, tokens):
    pair = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).json()
    assert pair["refresh_token"] != tokens["refresh_token"]
    assert client.get("/users/me", headers=bearer(pair["access_token"])).status_code == 200


def test_replayed_refresh_token_revokes_the_whole_family(client, tokens):
    newer = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).json()

    replay = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 401

    # The newer token belongs to the same family, so it stops working as well.
    after = client.post("/auth/refresh", json={"refresh_token": newer["refresh_token"]})
    assert after.status_code == 401


def test_logout_blocks_the_access_token_and_the_refresh_token(client, tokens):
    headers = bearer(tokens["access_token"])
    assert client.post("/auth/logout", headers=headers).status_code == 204
    assert client.get("/users/me", headers=headers).status_code == 401
    refresh = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh.status_code == 401


def test_key_rotation_signs_no_one_out(client, tokens, ring):
    ring.rotate()

    assert client.get("/users/me", headers=bearer(tokens["access_token"])).status_code == 200
    pair = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).json()
    assert client.get("/users/me", headers=bearer(pair["access_token"])).status_code == 200


def test_jwks_publishes_both_keys_and_no_private_parts(client, ring):
    ring.rotate()
    keys = client.get("/.well-known/jwks.json").json()["keys"]
    assert len(keys) == 2
    assert all("d" not in key and "p" not in key for key in keys)


def test_retired_key_stops_old_tokens(client, tokens, ring):
    old_kid = ring.active_kid
    ring.rotate()
    ring.retire(old_kid)
    assert client.get("/users/me", headers=bearer(tokens["access_token"])).status_code == 401
