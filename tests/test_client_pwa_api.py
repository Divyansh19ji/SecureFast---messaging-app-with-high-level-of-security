"""Tests for the Local Device Client FastAPI App & Installable PWA Endpoints."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from securefast.client.app import compute_advertised_relay_url, create_client_app
from securefast.config import ClientConfig


@pytest.mark.parametrize(
    "relay_url,lan_ip,expected",
    [
        ("ws://127.0.0.1:8765", "192.168.1.42", "ws://192.168.1.42:8765"),
        ("ws://localhost:8765", "10.0.0.5", "ws://10.0.0.5:8765"),
        ("wss://relay.example.com:443", "192.168.1.42", "wss://relay.example.com:443"),
        ("ws://192.168.1.10:9000", "192.168.1.42", "ws://192.168.1.10:9000"),
    ],
)
def test_compute_advertised_relay_url(relay_url: str, lan_ip: str, expected: str):
    assert compute_advertised_relay_url(relay_url, lan_ip) == expected


@pytest.mark.parametrize(
    "route,expected_ct",
    [
        ("/", "text/html"),
        ("/manifest.json", "application/manifest+json"),
        ("/sw.js", "application/javascript"),
        ("/icon.svg", "image/svg+xml"),
        ("/static/style.css", "text/css"),
        ("/static/app.js", "javascript"),
    ],
)
def test_pwa_shell_assets_served_cleanly(route: str, expected_ct: str):
    app = create_client_app(ClientConfig())
    with TestClient(app) as client:
        resp = client.get(route)
        assert resp.status_code == 200
        assert expected_ct in resp.headers["content-type"].lower()


def test_client_health_and_initial_state():
    app = create_client_app(ClientConfig(default_username="Divyansh", default_role="ADMIN"))
    with TestClient(app) as client:
        h = client.get("/health").json()
        assert h["status"] == "ok"
        assert "SecureFast-C11-Core" in h["native_engine"]

        st = client.get("/api/state").json()
        assert st["username"] == "Divyansh"
        assert st["role"] == "ADMIN"
        assert st["handshake_complete"] is False
        assert st["messages"] == []


@pytest.mark.parametrize("role", ["ADMIN", "MEMBER", "GUEST"])
def test_client_identity_update_rotates_role_and_keys(role: str):
    app = create_client_app(ClientConfig())
    with TestClient(app) as client:
        resp = client.post(
            "/api/identity",
            json={"username": "Friend1", "role": role, "relay_url": "ws://127.0.0.1:8765"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "Friend1"
        assert data["role"] == role
        assert len(data["public_key_fingerprint"]) > 10


def test_client_send_before_handshake_returns_400():
    app = create_client_app(ClientConfig(default_username="Alice", default_role="ADMIN"))
    with TestClient(app) as client:
        resp = client.post(
            "/api/messages/send",
            json={"text": "hello", "required_role": "MEMBER"},
        )
        assert resp.status_code == 400
