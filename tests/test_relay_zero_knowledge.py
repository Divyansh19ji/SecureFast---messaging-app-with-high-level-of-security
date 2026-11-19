"""Tests for 'The Path' Zero-Knowledge Relay Server (Section 3.3 & Table 6.1)."""

from __future__ import annotations

import base64
import json
import os
import time

from fastapi.testclient import TestClient

from securefast.config import RelayConfig
from securefast.native_bridge import sha256_hex
from securefast.relay.app import create_relay_app


def _make_fake_chunk(path_id: str, msg_id: str, idx: int, total: int, ct_bytes: bytes) -> dict:
    iv = os.urandom(12)
    return {
        "message_id": msg_id,
        "path_id": path_id,
        "chunk_index": idx,
        "total_chunks": total,
        "iv_b64": base64.b64encode(iv).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ct_bytes).decode("ascii"),
        "checksum_hex": sha256_hex(iv + ct_bytes),
        "required_role": "MEMBER",
        "self_destruct_sec": 0,
        "kind": "chat",
    }


def test_health_and_security_headers():
    app = create_relay_app(RelayConfig())
    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["messages_decrypted_by_server"] == 0
        assert resp.headers["x-content-type-options"] == "nosniff"
        assert resp.headers["x-frame-options"] == "DENY"
        assert resp.headers["referrer-policy"] == "no-referrer"
        assert "no-store" in resp.headers["cache-control"]


def test_relay_enforces_strict_1_to_1_two_peer_limit():
    app = create_relay_app(RelayConfig())
    with TestClient(app) as client:
        with client.websocket_connect("/ws") as ws1:
            ws1.send_json({"type": "path:create", "payload": {"peer_id": "p1", "username": "Alice"}})
            created = ws1.receive_json()
            assert created["type"] == "path:created"
            pid = created["path_id"]

            with client.websocket_connect("/ws") as ws2:
                ws2.send_json(
                    {"type": "path:join", "path_id": pid, "payload": {"peer_id": "p2", "username": "Bob"}}
                )
                joined = ws2.receive_json()
                assert joined["type"] == "path:joined"

                # Third peer must be rejected!
                with client.websocket_connect("/ws") as ws3:
                    ws3.send_json(
                        {"type": "path:join", "path_id": pid, "payload": {"peer_id": "p3", "username": "Eve"}}
                    )
                    err = ws3.receive_json()
                    assert err["type"] == "error"
                    assert "full" in err["payload"]["message"].lower()


def test_relay_rejects_chunks_larger_than_2kb():
    app = create_relay_app(RelayConfig(max_chunk_bytes=2048))
    with TestClient(app) as client:
        with client.websocket_connect("/ws") as ws1:
            ws1.send_json({"type": "path:create", "payload": {"peer_id": "p1", "username": "Alice"}})
            pid = ws1.receive_json()["path_id"]

            oversized = _make_fake_chunk(pid, "msg-big", 0, 1, b"Z" * 2049)
            ws1.send_json({"type": "chunk:send", "path_id": pid, "payload": oversized})
            err = ws1.receive_json()
            assert err["type"] == "error"
            assert "exceeds" in err["payload"]["message"].lower()


def test_relay_offline_queue_delivers_when_peer_reconnects():
    app = create_relay_app(RelayConfig())
    with TestClient(app) as client:
        with client.websocket_connect("/ws") as ws1:
            ws1.send_json({"type": "path:create", "payload": {"peer_id": "alice", "username": "Alice"}})
            pid = ws1.receive_json()["path_id"]

            # Bob joins then disconnects
            with client.websocket_connect("/ws") as ws2:
                ws2.send_json({"type": "path:join", "path_id": pid, "payload": {"peer_id": "bob", "username": "Bob"}})
                assert ws2.receive_json()["type"] == "path:joined"
                assert ws1.receive_json()["type"] == "path:peer_connected"

            # Alice observes peer_disconnected
            assert ws1.receive_json()["type"] == "path:peer_disconnected"

            # Alice sends encrypted chunk while Bob is offline
            chunk = _make_fake_chunk(pid, "msg-off", 0, 1, os.urandom(128))
            ws1.send_json({"type": "chunk:send", "path_id": pid, "payload": chunk})
            queued_ack = ws1.receive_json()
            assert queued_ack["type"] == "chunk:queued_offline"

            # Bob reconnects with his peer_id and immediately receives the queued ciphertext chunk!
            with client.websocket_connect("/ws") as ws2_re:
                ws2_re.send_json(
                    {"type": "path:join", "path_id": pid, "payload": {"peer_id": "bob", "username": "Bob"}}
                )
                assert ws2_re.receive_json()["type"] == "path:joined"
                delivered = ws2_re.receive_json()
                assert delivered["type"] == "chunk:receive"
                assert delivered["payload"]["message_id"] == "msg-off"


def test_relay_ttl_expiry_purges_inactive_paths():
    app = create_relay_app(RelayConfig(path_ttl_seconds=1))
    with TestClient(app) as client:
        with client.websocket_connect("/ws") as ws1:
            ws1.send_json({"type": "path:create", "payload": {"peer_id": "p1", "username": "Alice"}})
            pid = ws1.receive_json()["path_id"]
        # Force expiry timestamp into the past
        app.state.relay.paths[pid].expires_at = time.time() - 5
        purged = app.state.relay.purge_expired()
        assert purged == 1
        assert pid not in app.state.relay.paths


def test_relay_rate_limiting():
    app = create_relay_app(RelayConfig(rate_limit_max_requests=5, rate_limit_window_seconds=60))
    with TestClient(app) as client:
        codes = [client.get("/health").status_code for _ in range(7)]
        assert codes[:5] == [200, 200, 200, 200, 200]
        assert 429 in codes[5:]


def test_relay_stats_contain_zero_plaintext():
    """Table 6.1 Quality Target: 0 plaintext leaks in relay memory/stats."""
    app = create_relay_app(RelayConfig())
    with TestClient(app) as client:
        with client.websocket_connect("/ws") as ws1:
            ws1.send_json({"type": "path:create", "payload": {"peer_id": "p1", "username": "Alice"}})
            pid = ws1.receive_json()["path_id"]
            chunk = _make_fake_chunk(pid, "msg-zk", 0, 1, os.urandom(256))
            ws1.send_json({"type": "chunk:send", "path_id": pid, "payload": chunk})

        stats = client.get("/api/relay/stats").json()
        assert stats["messages_decrypted_by_server"] == 0
        assert stats["disk_writes"] == 0
        assert stats["total_chunks_relayed"] == 1
        serialized = json.dumps(stats)
        assert "ciphertext_b64" not in serialized
