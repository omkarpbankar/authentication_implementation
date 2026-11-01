import base64

from fastapi.testclient import TestClient

from apps.phase1_fundamentals.exercise1_basic_auth import app

client = TestClient(app)
GOOD = ("asha", "correct-horse-battery")


def test_public_route_needs_no_credentials():
    assert client.get("/public").status_code == 200


def test_correct_credentials_succeed():
    response = client.get("/secret", auth=GOOD)
    assert response.status_code == 200
    assert "asha" in response.json()["message"]


def test_missing_credentials_are_rejected():
    response = client.get("/secret")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Basic"


def test_wrong_password_and_unknown_user_look_identical():
    wrong_password = client.get("/secret", auth=("asha", "wrong"))
    unknown_user = client.get("/secret", auth=("nobody", "wrong"))
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json() == unknown_user.json()


def test_basic_header_is_only_encoded_not_encrypted():
    encoded = base64.b64encode(b"asha:correct-horse-battery").decode()

    response = client.get("/secret", headers={"Authorization": f"Basic {encoded}"})

    # The server accepts this value, and anyone who sees it can reverse it with no key.
    assert response.status_code == 200
    assert base64.b64decode(encoded).decode() == "asha:correct-horse-battery"
