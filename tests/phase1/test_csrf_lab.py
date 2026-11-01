"""These tests cover the server's own checks.

They send the cookie by hand, which shows what happens if a cookie reaches the server.
SameSite is enforced by browsers, so pytest cannot test it. The lesson covers that in a browser.
"""

import re

import pytest
from fastapi.testclient import TestClient

from apps.phase1_fundamentals.csrf_lab import bank

ATTACK = {"to": "attacker", "amount": 100}


@pytest.fixture
def client():
    bank.sessions.clear()
    bank.balances.clear()
    bank.history.clear()
    test_client = TestClient(bank.app)
    test_client.post("/login", data={"username": "asha"})
    return test_client


def csrf_token_from_page(client):
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get("/").text).group(1)


def test_vulnerable_get_moves_money_with_only_a_cookie(client):
    assert client.get("/vulnerable/transfer", params=ATTACK).status_code == 200
    assert bank.balances["asha"] == 900


def test_vulnerable_post_moves_money_when_a_cookie_arrives(client):
    assert client.post("/vulnerable/transfer-post", data=ATTACK).status_code == 200
    assert bank.balances["asha"] == 900


def test_safe_route_rejects_a_missing_token(client):
    assert client.post("/safe/transfer", data=ATTACK).status_code == 403
    assert bank.balances["asha"] == 1000


def test_safe_route_rejects_a_wrong_token(client):
    response = client.post("/safe/transfer", data={**ATTACK, "csrf_token": "guess"})
    assert response.status_code == 403
    assert bank.balances["asha"] == 1000


def test_safe_route_rejects_another_users_token():
    bank.sessions.clear()
    bank.balances.clear()
    attacker = TestClient(bank.app)
    attacker.post("/login", data={"username": "attacker"})
    attacker_token = csrf_token_from_page(attacker)

    victim = TestClient(bank.app)
    victim.post("/login", data={"username": "asha"})
    response = victim.post("/safe/transfer", data={**ATTACK, "csrf_token": attacker_token})

    assert response.status_code == 403
    assert bank.balances["asha"] == 1000


def test_safe_route_accepts_the_token_from_the_banks_own_page(client):
    token = csrf_token_from_page(client)
    response = client.post("/safe/transfer", data={**ATTACK, "csrf_token": token})
    assert response.status_code == 200
    assert bank.balances["asha"] == 900


def test_every_transfer_requires_a_session():
    bank.sessions.clear()
    anonymous = TestClient(bank.app)
    assert anonymous.get("/vulnerable/transfer", params=ATTACK).status_code == 401
    assert anonymous.post("/vulnerable/transfer-post", data=ATTACK).status_code == 401
    assert anonymous.post("/safe/transfer", data=ATTACK).status_code == 401
