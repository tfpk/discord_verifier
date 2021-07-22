import pytest
import tempfile
import login_function
import create_subsite
import os

from pathlib import Path

os.environ["DISCORD_BOT_KEY"] = "asdf"

import server


ARC_ADMIN = "z9999999"
SERVER_ADMIN = "z5205060"
NON_ADMIN = "z1234567"
NO_LOGIN = "z0000000"


@pytest.fixture
def client():
    with server.app.test_client() as client:
        yield client


@pytest.fixture
def with_site(tmpdir):
    os.chdir(tmpdir)
    Path("arc_admin").mkdir()
    Path("arc_admin/admin_rules.html").touch()
    Path("arc_admin/admins.json").write_text(f'["{ARC_ADMIN}"]')
    yield create_subsite.create_subsite(
        "test", "TestSoc", "123456", "Verified", ["z5205060"], b"asdf", "tom@tfpk.dev"
    )


@pytest.fixture
def verifier_patches(monkeypatch):
    def login(zid, zpass):
        if zid in [ARC_ADMIN, SERVER_ADMIN, NON_ADMIN]:
            return {'name': "Person", 'email': "a@b.com"}

        return None

    monkeypatch.setattr(
        server, "get_verified_role", lambda server, role_name: {"name": "asdf"}
    )
    monkeypatch.setattr(login_function, "authenticate", login)


def test_verify_site(client):
    for site in ["/verify/", "/admin/"]:
        resp = client.post(
            site, json={"site": "asdf%", "settings": {}}, follow_redirects=True
        )
        assert resp.status_code == 200
        assert "not been configured" in resp.get_json()["error"]["text"]


def test_admin_login(client, with_site, verifier_patches):
    resp = client.post(
        "/admin/",
        json={
            "site": with_site["short_name"],
            "login": {"zid": NO_LOGIN, "zpass": "bad_password",},
            "settings": {},
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert "not recognised" in resp.get_json()["error"]["text"]

    resp = client.post(
        "/admin/",
        json={
            "site": with_site["short_name"],
            "login": {"zid": NON_ADMIN, "zpass": "bad_password",},
            "settings": {},
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert "not an admin" in resp.get_json()["error"]["text"]


def test_admin_login_key(client, with_site, verifier_patches):
    resp = client.post(
        "/admin/",
        json={
            "site": with_site["short_name"],
            "login": {"zid": SERVER_ADMIN, "zpass": "bad_password", "key": "asdfasdf"},
            "settings": {},
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert "incorrect, or not configured" in resp.get_json()["error"]["text"]

VALID_LOGIN = {
    "confirmation": {
        "confirm_details": False,
        "confirm_terms": False,
        "ok": False
    },
    "discord": {
        "discord_id": None,
        "discord_username": None,
        "info": None,
        "ok": False
    },
    "error": None,
    "login": {
        "email": None,
        "name": None,
        "ok": False,
        "zid": NON_ADMIN,
        "zpass": "password"
    },
    "site": "test"
}

def test_interactions(client, with_site, verifier_patches):
    resp = client.post(
        "/verify/",
        json=VALID_LOGIN,
        follow_redirects=True,
    )
    assert resp.status_code == 200
    resp_json = resp.get_json()
    assert resp_json["login"]["ok"]
    assert not resp_json["error"]
    assert not resp_json["info"]

    # req_json = resp_json
    # req_json["discord"]["discord_username"] = "tfpk"

    # resp = client.post(
    #     "/verify/",
    #     json=req_json,
    #     follow_redirects=True,
    # )
