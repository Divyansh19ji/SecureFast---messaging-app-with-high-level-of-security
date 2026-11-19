"""
Full End-to-End Two-Party Tests (Alice <-> Live Zero-Knowledge Relay <-> Bob)
& Table 6.1 Performance Benchmarks.
"""

from __future__ import annotations

import asyncio
import json
import socket
import time

import pytest
import uvicorn

from securefast.client.session import DeviceSessionManager, parse_invite_input
from securefast.config import ClientConfig, RelayConfig
from securefast.crypto_engine import RoleAccessDeniedError
from securefast.models import MessageStatus, Role
from securefast.relay.app import create_relay_app


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _start_live_relay():
    port = _find_free_port()
    app = create_relay_app(RelayConfig(host="127.0.0.1", port=port))
    config = uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    for _ in range(50):
        if server.started:
            break
        await asyncio.sleep(0.05)
    return app, server, task, f"ws://127.0.0.1:{port}"


async def _stop_live_relay(server: uvicorn.Server, task: asyncio.Task):
    server.should_exit = True
    await task


async def _wait_until(predicate, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.03)
    raise AssertionError("Timed out waiting for async condition")


def test_invite_code_parser():
    pid, relay = parse_invite_input("sf://192.168.1.42:8765/SF-ABCD-1234-9999")
    assert pid == "SF-ABCD-1234-9999"
    assert relay == "ws://192.168.1.42:8765"

    pid2, relay2 = parse_invite_input("SF-ABCD-1234-9999")
    assert pid2 == "SF-ABCD-1234-9999"
    assert relay2 is None


def test_full_two_party_e2e_chat_rbac_zero_leaks_and_500char_latency():
    async def run():
        relay_app, server, srv_task, relay_url = await _start_live_relay()
        alice = DeviceSessionManager(ClientConfig(relay_url=relay_url, default_username="Alice", default_role="ADMIN"))
        bob = DeviceSessionManager(ClientConfig(relay_url=relay_url, default_username="Bob", default_role="MEMBER"))
        alice.start_background_tasks()
        bob.start_background_tasks()

        try:
            # 1. Alice creates path & gets invite code
            await alice.create_path()
            invite = alice.get_invite_info()
            assert invite is not None
            assert invite["invite_code"].startswith("sf://")

            # 2. Bob joins using the invite code
            await bob.join_path(invite["invite_code"])

            # 3. Wait for ECDH P-256 handshake completion on both devices
            await _wait_until(lambda: alice.handshake_complete and bob.handshake_complete)
            assert alice.keyring is not None and bob.keyring is not None
            assert alice.keyring.safety_number == bob.keyring.safety_number

            # 4. Alice sends a confidential MEMBER message
            secret_msg = "The deal closes Friday at $42M — confirm wire #7781!"
            sent = await alice.send_message(secret_msg, required_role=Role.MEMBER)
            msg_id = sent["message_id"]

            # 5. Bob receives it LOCKED until tapped
            await _wait_until(lambda: len(bob.messages) == 1)
            bob_msg_locked = bob.messages[0].to_ui_dict()
            assert bob_msg_locked["revealed"] is False
            assert bob_msg_locked["text"] is None

            # 6. Bob taps to reveal -> exact plaintext + Alice receives READ receipt!
            revealed = await bob.reveal_message(msg_id)
            assert revealed["revealed"] is True
            assert revealed["text"] == secret_msg
            await _wait_until(lambda: alice._messages_by_id[msg_id].status == MessageStatus.READ)

            # 7. Role-Based Decryption E2E: Alice sends ADMIN-only Vault secret -> Bob (MEMBER) is blocked!
            admin_secret = "MASTER-ROOT-PASSWORD-99999"
            admin_sent = await alice.send_message(
                admin_secret,
                required_role=Role.ADMIN,
                kind="vault",
                vault_title="Root Vault",
            )
            await _wait_until(lambda: len(bob.messages) == 2)
            bob_admin_rec = bob._messages_by_id[admin_sent["message_id"]]
            assert bob_admin_rec.status == MessageStatus.LOCKED_ROLE
            assert bob_admin_rec.text is None
            with pytest.raises(RoleAccessDeniedError):
                await bob.reveal_message(admin_sent["message_id"])

            # 8. Table 6.1 Quality Target: 0 plaintext leaks in Relay memory/stats!
            stats_blob = json.dumps(relay_app.state.relay.stats())
            assert "Friday" not in stats_blob
            assert "$42M" not in stats_blob
            assert "MASTER-ROOT-PASSWORD" not in stats_blob
            assert relay_app.state.relay.stats()["messages_decrypted_by_server"] == 0

            # 9. Table 6.1 Performance Target: 500-char message delivered end-to-end in < 2.0 s!
            msg_500 = (
                "SecureFast end-to-end encrypted Anti-OCR 500 character benchmark payload! "
                "Every token is rendered as a C11 secret glyph and split into 2 KB chunks. "
            ) * 4
            msg_500 = msg_500[:500]
            t0 = time.perf_counter()
            sent_500 = await alice.send_message(msg_500, required_role=Role.MEMBER)
            await _wait_until(lambda: sent_500["message_id"] in bob._messages_by_id)
            elapsed = time.perf_counter() - t0
            assert elapsed < 2.0, f"500-char E2E delivery took {elapsed:.3f}s (target < 2.0s)"
            rev_500 = await bob.reveal_message(sent_500["message_id"])
            assert rev_500["text"] == msg_500

            # 10. Self-destruct timer & memory scrubbing E2E
            burn_sent = await alice.send_message(
                "Burn this secret immediately!",
                required_role=Role.MEMBER,
                self_destruct_sec=1,
            )
            await _wait_until(lambda: burn_sent["message_id"] in bob._messages_by_id)
            await bob.reveal_message(burn_sent["message_id"])
            await _wait_until(
                lambda: alice._messages_by_id[burn_sent["message_id"]].status == MessageStatus.BURNED
                and bob._messages_by_id[burn_sent["message_id"]].status == MessageStatus.BURNED,
                timeout=4.0,
            )
            assert alice._messages_by_id[burn_sent["message_id"]].text is None
            assert bob._messages_by_id[burn_sent["message_id"]].text is None

        finally:
            await alice.shutdown()
            await bob.shutdown()
            await _stop_live_relay(server, srv_task)

    asyncio.run(run())
