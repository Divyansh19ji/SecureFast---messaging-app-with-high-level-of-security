"""
Local Device Session Manager — End-to-End Pipeline Execution on Each Friend's Machine.

All sensitive operations happen strictly locally in Python + C11:
  - Ephemeral ECDH P-256 key generation (private key never leaves device)
  - HKDF-SHA256 role-isolated key & glyph seed derivation
  - C11 Anti-OCR Secret Glyph rendering & pixel-only decoding
  - AES-256-GCM 2 KB chunk encryption, SHA-256 integrity, ACK & resend protocol
  - Self-destruct timer with memory scrubbing
  - Role-Based Decryption (ADMIN / MEMBER / GUEST) for both Chat & Secure Vault
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Literal, Optional
from urllib.parse import urlparse

import segno
import websockets

from securefast.chunk_engine import (
    ChunkReassemblyBuffer,
    ChunkTamperedError,
    encrypt_and_chunk_bundle,
)
from securefast.config import ClientConfig
from securefast.crypto_engine import (
    CryptoError,
    DecryptionFailedError,
    DeviceKeyPair,
    RoleAccessDeniedError,
    SessionKeyring,
    generate_salt,
)
from securefast.glyph_engine import (
    decode_glyph_bundle,
    encode_text_to_glyph_tokens,
    pack_glyph_bundle,
)
from securefast.models import (
    EncryptedChunkPayload,
    MessageStatus,
    Role,
)
from securefast.native_bridge import GlyphDecodeError, native_version


@dataclass
class LocalMessageRecord:
    message_id: str
    direction: Literal["sent", "received"]
    sender_name: str
    text: Optional[str]
    required_role: Role
    kind: Literal["chat", "vault"]
    status: MessageStatus
    timestamp: float
    revealed: bool
    self_destruct_sec: int = 0
    expires_at: Optional[float] = None
    total_chunks: int = 0
    acked_chunks: int = 0
    latency_ms: float = 0.0
    decode_confidence: float = 1.0
    vault_title: Optional[str] = None
    # "5 Forms Inspector" local diagnostic data (scrubbed on self-destruct)
    inspector: dict[str, Any] = field(default_factory=dict)

    def to_ui_dict(self) -> dict[str, Any]:
        is_burned = self.status == MessageStatus.BURNED
        is_role_locked = self.status == MessageStatus.LOCKED_ROLE
        visible_text: Optional[str]
        if is_burned:
            visible_text = None
        elif is_role_locked:
            visible_text = None
        elif self.direction == "received" and not self.revealed:
            visible_text = None  # Hidden until tapped (Slide 17: "Tap to reveal")
        else:
            visible_text = self.text

        remaining = None
        if self.expires_at is not None and not is_burned:
            remaining = max(0, int(self.expires_at - time.time()))

        return {
            "message_id": self.message_id,
            "direction": self.direction,
            "sender_name": self.sender_name,
            "text": visible_text,
            "required_role": self.required_role.value,
            "kind": self.kind,
            "status": self.status.value,
            "timestamp": self.timestamp,
            "revealed": self.revealed,
            "self_destruct_sec": self.self_destruct_sec,
            "remaining_sec": remaining,
            "total_chunks": self.total_chunks,
            "acked_chunks": self.acked_chunks,
            "latency_ms": round(self.latency_ms, 2),
            "decode_confidence": round(self.decode_confidence, 4),
            "vault_title": self.vault_title,
            "has_inspector": bool(self.inspector) and not is_burned,
            "glyph_preview": (
                self.inspector.get("glyph_images", [])[:4]
                if (not is_burned and self.inspector)
                else []
            ),
        }


def _normalize_relay_ws_url(url: str) -> str:
    raw = url.strip()
    if not raw:
        return "ws://127.0.0.1:8765/ws"
    if raw.startswith("http://"):
        raw = "ws://" + raw[len("http://") :]
    elif raw.startswith("https://"):
        raw = "wss://" + raw[len("https://") :]
    elif not raw.startswith(("ws://", "wss://")):
        raw = "ws://" + raw
    parsed = urlparse(raw)
    if not parsed.path or parsed.path == "/":
        return raw.rstrip("/") + "/ws"
    return raw


def _make_qr_svg_data_url(content: str) -> str:
    qr = segno.make(content, error="m")
    buf = io.BytesIO()
    qr.save(buf, kind="svg", scale=5, border=2, dark="#0f172a", light="#ffffff", xmldecl=False)
    svg_b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/svg+xml;base64,{svg_b64}"


class DeviceSessionManager:
    """Manages one user's local SecureFast device state, crypto keyring, and Path WebSocket."""

    def __init__(self, config: ClientConfig) -> None:
        self.config = config
        self.peer_id: str = f"peer-{secrets.token_hex(6)}"
        self.username: str = config.default_username or ""
        try:
            self.role: Role = Role(config.default_role.upper())
        except ValueError:
            self.role = Role.ADMIN
        self.relay_url: str = config.relay_url

        self.keypair: DeviceKeyPair = DeviceKeyPair.generate()
        self.keyring: Optional[SessionKeyring] = None
        self._pending_salt: Optional[bytes] = None

        self.path_id: Optional[str] = None
        self.is_creator: bool = False
        self.peer_username: Optional[str] = None
        self.peer_role: Optional[str] = None
        self.peer_online: bool = False
        self.peer_typing: bool = False
        self.handshake_complete: bool = False
        self.connection_status: str = "disconnected"  # disconnected | connecting | waiting | connected

        self.messages: list[LocalMessageRecord] = []
        self._messages_by_id: dict[str, LocalMessageRecord] = {}
        self._outbound_chunks: dict[str, dict[int, EncryptedChunkPayload]] = {}
        self._outbound_acks: dict[str, set[int]] = {}
        self._inbound_buffers: dict[str, ChunkReassemblyBuffer] = {}
        self._gap_tasks: dict[str, asyncio.Task[Any]] = {}

        self._ws: Any = None
        self._recv_task: Optional[asyncio.Task[Any]] = None
        self._burn_task: Optional[asyncio.Task[Any]] = None
        self._ui_subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Lifecycle & UI Pub/Sub
    # ------------------------------------------------------------------

    def start_background_tasks(self) -> None:
        if self._burn_task is None or self._burn_task.done():
            self._burn_task = asyncio.create_task(self._self_destruct_loop())

    async def shutdown(self) -> None:
        await self.disconnect(notify_relay=False)
        if self._burn_task and not self._burn_task.done():
            self._burn_task.cancel()
            try:
                await self._burn_task
            except asyncio.CancelledError:
                pass
        if self.keyring:
            self.keyring.scrub_all()
            self.keyring = None

    def subscribe_ui(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=200)
        self._ui_subscribers.add(q)
        return q

    def unsubscribe_ui(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        self._ui_subscribers.discard(q)

    async def _broadcast_ui(self, event_type: str, data: Any) -> None:
        packet = {"type": event_type, "data": data}
        dead: list[asyncio.Queue[dict[str, Any]]] = []
        for q in list(self._ui_subscribers):
            try:
                q.put_nowait(packet)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._ui_subscribers.discard(q)

    # ------------------------------------------------------------------
    # Onboarding & Identity
    # ------------------------------------------------------------------

    async def setup_identity(self, username: str, role: Role, relay_url: Optional[str] = None) -> dict[str, Any]:
        clean = username.strip()[:40]
        if not clean:
            raise ValueError("Username cannot be empty")
        self.username = clean
        self.role = role
        if relay_url and relay_url.strip():
            self.relay_url = relay_url.strip()
        # Rotate ephemeral device keypair when identity/role changes while disconnected
        if self.connection_status == "disconnected":
            self.keypair = DeviceKeyPair.generate()
        state = self.get_state_snapshot()
        await self._broadcast_ui("state", state)
        return state

    # ------------------------------------------------------------------
    # Path Creation, Joining, Handshake & Disconnection
    # ------------------------------------------------------------------

    async def create_path(
        self,
        relay_url: Optional[str] = None,
        custom_path_id: Optional[str] = None,
    ) -> dict[str, Any]:
        if not self.username:
            raise ValueError("Please set your display name first")
        await self.disconnect(notify_relay=False)
        if relay_url and relay_url.strip():
            self.relay_url = relay_url.strip()

        self.keypair = DeviceKeyPair.generate()
        self._pending_salt = generate_salt()
        self.is_creator = True
        self.connection_status = "connecting"
        await self._broadcast_ui("state", self.get_state_snapshot())

        ws_url = _normalize_relay_ws_url(self.relay_url)
        try:
            self._ws = await websockets.connect(ws_url, ping_interval=20, ping_timeout=20)
        except Exception as exc:
            self.connection_status = "disconnected"
            await self._broadcast_ui("state", self.get_state_snapshot())
            raise ConnectionError(f"Could not connect to Relay at {ws_url}: {exc}") from exc

        req: dict[str, Any] = {
            "type": "path:create",
            "payload": {
                "peer_id": self.peer_id,
                "username": self.username,
                "role": self.role.value,
            },
        }
        if custom_path_id:
            req["path_id"] = custom_path_id.strip()

        await self._ws.send(json.dumps(req))
        raw_reply = await asyncio.wait_for(self._ws.recv(), timeout=8.0)
        reply = json.loads(raw_reply)
        if reply.get("type") != "path:created":
            await self._ws.close()
            self._ws = None
            self.connection_status = "disconnected"
            raise RuntimeError(reply.get("payload", {}).get("message", "Failed to create path"))

        self.path_id = reply["payload"]["path_id"]
        self.connection_status = "waiting"

        # Immediately send handshake:init so the relay caches it for the joining peer
        await self._send_handshake_init()
        self._recv_task = asyncio.create_task(self._relay_receive_loop())

        snap = self.get_state_snapshot()
        await self._broadcast_ui("state", snap)
        return snap

    async def join_path(
        self,
        path_id: str,
        relay_url: Optional[str] = None,
    ) -> dict[str, Any]:
        if not self.username:
            raise ValueError("Please set your display name first")
        clean_path, parsed_relay = parse_invite_input(path_id)
        if parsed_relay:
            self.relay_url = parsed_relay
        elif relay_url and relay_url.strip():
            self.relay_url = relay_url.strip()

        if not clean_path:
            raise ValueError("Please enter a valid Path ID or Invite Link")

        await self.disconnect(notify_relay=False)
        self.keypair = DeviceKeyPair.generate()
        self.is_creator = False
        self.connection_status = "connecting"
        await self._broadcast_ui("state", self.get_state_snapshot())

        ws_url = _normalize_relay_ws_url(self.relay_url)
        try:
            self._ws = await websockets.connect(ws_url, ping_interval=20, ping_timeout=20)
        except Exception as exc:
            self.connection_status = "disconnected"
            await self._broadcast_ui("state", self.get_state_snapshot())
            raise ConnectionError(f"Could not connect to Relay at {ws_url}: {exc}") from exc

        await self._ws.send(
            json.dumps(
                {
                    "type": "path:join",
                    "path_id": clean_path,
                    "payload": {
                        "path_id": clean_path,
                        "peer_id": self.peer_id,
                        "username": self.username,
                        "role": self.role.value,
                    },
                }
            )
        )
        raw_reply = await asyncio.wait_for(self._ws.recv(), timeout=8.0)
        reply = json.loads(raw_reply)
        if reply.get("type") != "path:joined":
            await self._ws.close()
            self._ws = None
            self.connection_status = "disconnected"
            raise RuntimeError(reply.get("payload", {}).get("message", "Failed to join path"))

        payload = reply["payload"]
        self.path_id = payload["path_id"]
        self.peer_online = bool(payload.get("peer_online"))
        self.peer_username = payload.get("peer_username")
        self.peer_role = payload.get("peer_role")
        self.connection_status = "connected" if self.peer_online else "waiting"

        self._recv_task = asyncio.create_task(self._relay_receive_loop())
        snap = self.get_state_snapshot()
        await self._broadcast_ui("state", snap)
        return snap

    async def disconnect(self, notify_relay: bool = False) -> None:
        if self._ws is not None:
            if notify_relay and self.path_id:
                try:
                    await self._ws.send(
                        json.dumps({"type": "path:destroy", "path_id": self.path_id, "payload": {}})
                    )
                except Exception:
                    pass
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None

        if self._recv_task and not self._recv_task.done():
            self._recv_task.cancel()
            try:
                await self._recv_task
            except asyncio.CancelledError:
                pass
        self._recv_task = None

        for task in list(self._gap_tasks.values()):
            task.cancel()
        self._gap_tasks.clear()

        if self.keyring:
            self.keyring.scrub_all()
            self.keyring = None

        self.path_id = None
        self.peer_username = None
        self.peer_role = None
        self.peer_online = False
        self.peer_typing = False
        self.handshake_complete = False
        self.connection_status = "disconnected"
        self.messages.clear()
        self._messages_by_id.clear()
        self._outbound_chunks.clear()
        self._outbound_acks.clear()
        self._inbound_buffers.clear()

    async def _send_handshake_init(self) -> None:
        if not self._ws or not self.path_id or not self._pending_salt:
            return
        await self._ws.send(
            json.dumps(
                {
                    "type": "handshake:init",
                    "path_id": self.path_id,
                    "payload": {
                        "peer_id": self.peer_id,
                        "username": self.username,
                        "role": self.role.value,
                        "public_key_b64": self.keypair.public_key_b64,
                        "salt_b64": base64.b64encode(self._pending_salt).decode("ascii"),
                    },
                }
            )
        )

    async def _relay_receive_loop(self) -> None:
        try:
            assert self._ws is not None
            async for raw in self._ws:
                frame = json.loads(raw)
                await self._handle_relay_frame(frame)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.connection_status = "disconnected"
            self.peer_online = False
            await self._broadcast_ui("state", self.get_state_snapshot())

    async def _handle_relay_frame(self, frame: dict[str, Any]) -> None:
        etype = frame.get("type")
        payload = frame.get("payload") or {}

        if etype == "path:peer_connected":
            self.peer_online = True
            self.peer_username = payload.get("username") or self.peer_username
            self.peer_role = payload.get("role") or self.peer_role
            self.connection_status = "connected"
            if self.is_creator:
                await self._send_handshake_init()
            await self._broadcast_ui("state", self.get_state_snapshot())
            return

        if etype == "path:peer_disconnected":
            self.peer_online = False
            self.peer_typing = False
            await self._broadcast_ui("state", self.get_state_snapshot())
            return

        if etype == "path:destroyed":
            await self._broadcast_ui(
                "alert", {"level": "warning", "message": "Peer destroyed the ephemeral path."}
            )
            await self.disconnect(notify_relay=False)
            await self._broadcast_ui("state", self.get_state_snapshot())
            return

        if etype == "handshake:init":
            peer_pub_b64 = payload["public_key_b64"]
            salt = base64.b64decode(payload["salt_b64"])
            self.peer_username = payload.get("username") or "Peer"
            self.peer_role = payload.get("role") or "ADMIN"
            self.peer_online = True
            self.connection_status = "connected"

            self.keyring = SessionKeyring.establish(
                local_keypair=self.keypair,
                peer_public_key_b64=peer_pub_b64,
                salt=salt,
                local_role=self.role,
            )
            self.handshake_complete = True

            if self._ws and self.path_id:
                await self._ws.send(
                    json.dumps(
                        {
                            "type": "handshake:response",
                            "path_id": self.path_id,
                            "payload": {
                                "peer_id": self.peer_id,
                                "username": self.username,
                                "role": self.role.value,
                                "public_key_b64": self.keypair.public_key_b64,
                            },
                        }
                    )
                )
            await self._broadcast_ui("state", self.get_state_snapshot())
            return

        if etype == "handshake:response":
            peer_pub_b64 = payload["public_key_b64"]
            self.peer_username = payload.get("username") or "Peer"
            self.peer_role = payload.get("role") or "MEMBER"
            self.peer_online = True
            self.connection_status = "connected"
            assert self._pending_salt is not None

            self.keyring = SessionKeyring.establish(
                local_keypair=self.keypair,
                peer_public_key_b64=peer_pub_b64,
                salt=self._pending_salt,
                local_role=self.role,
            )
            self.handshake_complete = True
            await self._broadcast_ui("state", self.get_state_snapshot())
            return

        if etype == "chunk:receive":
            await self._handle_incoming_chunk(payload)
            return

        if etype == "chunk:ack":
            msg_id = payload.get("message_id")
            idx = payload.get("chunk_index")
            status = payload.get("status")
            if msg_id in self._messages_by_id and isinstance(idx, int):
                if status == "CHECKSUM_FAILED":
                    await self._resend_chunks(msg_id, [idx])
                    return
                acked = self._outbound_acks.setdefault(msg_id, set())
                acked.add(idx)
                rec = self._messages_by_id[msg_id]
                rec.acked_chunks = len(acked)
                if rec.acked_chunks >= rec.total_chunks and rec.status == MessageStatus.SENDING:
                    rec.status = MessageStatus.DELIVERED
                await self._broadcast_ui("message:update", rec.to_ui_dict())
            return

        if etype == "chunk:resend_req":
            msg_id = payload.get("message_id")
            missing = payload.get("missing_indices") or []
            if msg_id and missing:
                await self._resend_chunks(msg_id, [int(i) for i in missing])
            return

        if etype == "message:read":
            msg_id = payload.get("message_id")
            if msg_id in self._messages_by_id:
                rec = self._messages_by_id[msg_id]
                if rec.status != MessageStatus.BURNED:
                    rec.status = MessageStatus.READ
                    await self._broadcast_ui("message:update", rec.to_ui_dict())
            return

        if etype == "peer:typing":
            self.peer_typing = bool(payload.get("typing", False))
            await self._broadcast_ui("typing", {"typing": self.peer_typing})
            return

        if etype == "error":
            await self._broadcast_ui(
                "alert", {"level": "error", "message": payload.get("message", "Relay error")}
            )

    # ------------------------------------------------------------------
    # Sending Pipeline ("One Message, Five Forms")
    # ------------------------------------------------------------------

    async def send_message(
        self,
        text: str,
        required_role: Role = Role.MEMBER,
        self_destruct_sec: int = 0,
        kind: Literal["chat", "vault"] = "chat",
        vault_title: Optional[str] = None,
    ) -> dict[str, Any]:
        if not self._ws or not self.path_id or not self.handshake_complete or not self.keyring:
            raise RuntimeError("Secure handshake is not complete yet. Connect with a peer first.")
        if not text:
            raise ValueError("Message cannot be empty")
        if not self.keyring.can_access(required_role):
            raise RoleAccessDeniedError(
                f"Your role ({self.role.value}) cannot author '{required_role.value}' clearance items"
            )

        t0 = time.perf_counter()
        message_id = f"msg-{secrets.token_hex(6)}"
        payload_text = f"[{vault_title}]\n{text}" if (kind == "vault" and vault_title) else text

        # Step 2 & 3: Tokenize + Render Key-Derived Secret Glyph PNG Images in C11
        mat = self.keyring.get_role_material(required_role)
        tokens, glyph_tokens = encode_text_to_glyph_tokens(payload_text, bytes(mat.glyph_seed))
        bundle = pack_glyph_bundle(glyph_tokens)

        # Step 4 & 5: AES-256-GCM + Fresh 96-bit IV + C11 SHA-256 + <= 2 KB Chunks
        chunks = encrypt_and_chunk_bundle(
            bundle_bytes=bundle,
            path_id=self.path_id,
            message_id=message_id,
            keyring=self.keyring,
            required_role=required_role,
            self_destruct_sec=self_destruct_sec,
            kind=kind,
            max_ciphertext_bytes=self.config.max_chunk_bytes,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        expires_at = (time.time() + self_destruct_sec) if self_destruct_sec > 0 else None
        rec = LocalMessageRecord(
            message_id=message_id,
            direction="sent",
            sender_name=self.username,
            text=text,
            required_role=required_role,
            kind=kind,
            status=MessageStatus.SENDING,
            timestamp=time.time(),
            revealed=True,
            self_destruct_sec=self_destruct_sec,
            expires_at=expires_at,
            total_chunks=len(chunks),
            acked_chunks=0,
            latency_ms=elapsed_ms,
            vault_title=vault_title,
            inspector={
                "form1_plaintext_len": len(payload_text),
                "form2_tokens": tokens[:40],
                "token_count": len(tokens),
                "glyph_images": [
                    {
                        "index": gt.token_index,
                        "width": gt.width,
                        "height": gt.height,
                        "png_bytes": len(gt.png_bytes),
                        "data_url": gt.png_data_url,
                    }
                    for gt in glyph_tokens[:16]
                ],
                "bundle_bytes": len(bundle),
                "chunks": [
                    {
                        "chunk_index": c.chunk_index,
                        "total_chunks": c.total_chunks,
                        "iv_b64": c.iv_b64,
                        "ciphertext_preview": c.ciphertext_b64[:36] + "...",
                        "ciphertext_bytes": len(base64.b64decode(c.ciphertext_b64)),
                        "checksum_hex": c.checksum_hex,
                    }
                    for c in chunks[:20]
                ],
            },
        )
        self.messages.append(rec)
        self._messages_by_id[message_id] = rec
        self._outbound_chunks[message_id] = {c.chunk_index: c for c in chunks}
        self._outbound_acks[message_id] = set()

        await self._broadcast_ui("message:new", rec.to_ui_dict())

        # Stream numbered <= 2 KB encrypted chunks over The Path
        for c in chunks:
            await self._ws.send(
                json.dumps(
                    {
                        "type": "chunk:send",
                        "path_id": self.path_id,
                        "payload": c.model_dump(),
                    }
                )
            )

        return rec.to_ui_dict()

    async def _resend_chunks(self, message_id: str, indices: list[int]) -> None:
        if not self._ws or not self.path_id:
            return
        cache = self._outbound_chunks.get(message_id)
        if not cache:
            return
        for idx in indices:
            chunk = cache.get(idx)
            if chunk is not None:
                await self._ws.send(
                    json.dumps(
                        {
                            "type": "chunk:send",
                            "path_id": self.path_id,
                            "payload": chunk.model_dump(),
                        }
                    )
                )

    # ------------------------------------------------------------------
    # Receiving, Integrity Verification, Resend & Visual Glyph Decoding
    # ------------------------------------------------------------------

    async def _handle_incoming_chunk(self, payload: dict[str, Any]) -> None:
        try:
            chunk = EncryptedChunkPayload.model_validate(payload)
        except Exception:
            return

        buf = self._inbound_buffers.get(chunk.message_id)
        if buf is None:
            buf = ChunkReassemblyBuffer(
                message_id=chunk.message_id,
                path_id=chunk.path_id,
                total_chunks=chunk.total_chunks,
                required_role=chunk.required_role,
                self_destruct_sec=chunk.self_destruct_sec,
                kind=chunk.kind,
            )
            self._inbound_buffers[chunk.message_id] = buf

        try:
            buf.add_chunk(chunk)
        except ChunkTamperedError:
            # Reject tampered chunk and request resend!
            if self._ws and self.path_id:
                await self._ws.send(
                    json.dumps(
                        {
                            "type": "chunk:ack",
                            "path_id": self.path_id,
                            "payload": {
                                "message_id": chunk.message_id,
                                "chunk_index": chunk.chunk_index,
                                "status": "CHECKSUM_FAILED",
                            },
                        }
                    )
                )
            await self._broadcast_ui(
                "alert",
                {
                    "level": "warning",
                    "message": f"Tampered chunk #{chunk.chunk_index} rejected (SHA-256 mismatch). Requesting resend.",
                },
            )
            return

        # Acknowledge valid chunk
        if self._ws and self.path_id:
            await self._ws.send(
                json.dumps(
                    {
                        "type": "chunk:ack",
                        "path_id": self.path_id,
                        "payload": {
                            "message_id": chunk.message_id,
                            "chunk_index": chunk.chunk_index,
                            "status": "RECEIVED",
                        },
                    }
                )
            )

        if not buf.is_complete:
            # Schedule resend request if gaps remain after 1.5 s
            if chunk.message_id not in self._gap_tasks:
                self._gap_tasks[chunk.message_id] = asyncio.create_task(
                    self._request_missing_after_timeout(chunk.message_id)
                )
            return

        # All chunks received! Cancel gap watcher
        gap_task = self._gap_tasks.pop(chunk.message_id, None)
        if gap_task and not gap_task.done():
            gap_task.cancel()

        self._inbound_buffers.pop(chunk.message_id, None)
        await self._finalize_received_buffer(buf)

    async def _request_missing_after_timeout(self, message_id: str) -> None:
        try:
            for _ in range(3):
                await asyncio.sleep(1.5)
                buf = self._inbound_buffers.get(message_id)
                if buf is None or buf.is_complete:
                    return
                missing = buf.missing_indices()
                if missing and self._ws and self.path_id:
                    await self._ws.send(
                        json.dumps(
                            {
                                "type": "chunk:resend_req",
                                "path_id": self.path_id,
                                "payload": {
                                    "message_id": message_id,
                                    "missing_indices": missing,
                                },
                            }
                        )
                    )
        except asyncio.CancelledError:
            pass

    async def _finalize_received_buffer(self, buf: ChunkReassemblyBuffer) -> None:
        if not self.keyring:
            return
        t0 = time.perf_counter()
        raw_chunks = buf.ordered_raw_chunks()
        chunk_summary = [
            {
                "chunk_index": c.chunk_index,
                "total_chunks": c.total_chunks,
                "iv_b64": c.iv_b64,
                "ciphertext_preview": c.ciphertext_b64[:36] + "...",
                "ciphertext_bytes": len(base64.b64decode(c.ciphertext_b64)),
                "checksum_hex": c.checksum_hex,
            }
            for c in raw_chunks[:20]
        ]

        # Enforce Role-Based Decryption!
        if not self.keyring.can_access(buf.required_role):
            rec = LocalMessageRecord(
                message_id=buf.message_id,
                direction="received",
                sender_name=self.peer_username or "Peer",
                text=None,
                required_role=buf.required_role,
                kind=buf.kind,
                status=MessageStatus.LOCKED_ROLE,
                timestamp=time.time(),
                revealed=False,
                self_destruct_sec=buf.self_destruct_sec,
                total_chunks=buf.total_chunks,
                acked_chunks=buf.total_chunks,
                latency_ms=(time.perf_counter() - t0) * 1000.0,
                inspector={
                    "role_denied": True,
                    "required_role": buf.required_role.value,
                    "local_role": self.role.value,
                    "chunks": chunk_summary,
                },
            )
            self.messages.append(rec)
            self._messages_by_id[rec.message_id] = rec
            await self._broadcast_ui("message:new", rec.to_ui_dict())
            return

        try:
            bundle = buf.decrypt_and_reassemble(self.keyring)
            mat = self.keyring.get_role_material(buf.required_role)
            decoded = decode_glyph_bundle(bundle, bytes(mat.glyph_seed))
        except (DecryptionFailedError, RoleAccessDeniedError, GlyphDecodeError, CryptoError) as exc:
            await self._broadcast_ui(
                "alert", {"level": "error", "message": f"Decryption/glyph decode failed: {exc}"}
            )
            return

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        full_text = decoded.text
        vault_title: Optional[str] = None
        if buf.kind == "vault" and full_text.startswith("[") and "]\n" in full_text:
            header, body = full_text.split("]\n", 1)
            vault_title = header[1:]
            full_text = body

        rec = LocalMessageRecord(
            message_id=buf.message_id,
            direction="received",
            sender_name=self.peer_username or "Peer",
            text=full_text,
            required_role=buf.required_role,
            kind=buf.kind,
            status=MessageStatus.DELIVERED,
            timestamp=time.time(),
            revealed=False,  # Locked until tapped (Slide 17)
            self_destruct_sec=buf.self_destruct_sec,
            expires_at=None,  # Starts counting down once tapped/revealed
            total_chunks=buf.total_chunks,
            acked_chunks=buf.total_chunks,
            latency_ms=elapsed_ms,
            decode_confidence=decoded.avg_confidence,
            vault_title=vault_title,
            inspector={
                "form1_plaintext_len": len(decoded.text),
                "form2_tokens": decoded.tokens[:40],
                "token_count": len(decoded.tokens),
                "glyph_images": [
                    {
                        "index": gt.token_index,
                        "width": gt.width,
                        "height": gt.height,
                        "png_bytes": len(gt.png_bytes),
                        "data_url": gt.png_data_url,
                    }
                    for gt in decoded.glyph_images[:16]
                ],
                "bundle_bytes": len(bundle),
                "chunks": chunk_summary,
                "decode_confidence": round(decoded.avg_confidence, 4),
            },
        )
        self.messages.append(rec)
        self._messages_by_id[rec.message_id] = rec
        await self._broadcast_ui("message:new", rec.to_ui_dict())

    # ------------------------------------------------------------------
    # Tap-to-Reveal, Read Receipts, Typing, Inspector & Self-Destruct
    # ------------------------------------------------------------------

    async def reveal_message(self, message_id: str) -> dict[str, Any]:
        rec = self._messages_by_id.get(message_id)
        if rec is None:
            raise KeyError("Message not found")
        if rec.status == MessageStatus.LOCKED_ROLE:
            raise RoleAccessDeniedError(
                f"Cannot reveal: requires {rec.required_role.value} clearance (your role: {self.role.value})"
            )
        if rec.status == MessageStatus.BURNED:
            return rec.to_ui_dict()

        if not rec.revealed:
            rec.revealed = True
            rec.status = MessageStatus.READ
            if rec.self_destruct_sec > 0 and rec.expires_at is None:
                rec.expires_at = time.time() + rec.self_destruct_sec
            if self._ws and self.path_id:
                await self._ws.send(
                    json.dumps(
                        {
                            "type": "message:read",
                            "path_id": self.path_id,
                            "payload": {"message_id": message_id},
                        }
                    )
                )
            await self._broadcast_ui("message:update", rec.to_ui_dict())
        return rec.to_ui_dict()

    def get_inspector(self, message_id: str) -> dict[str, Any]:
        rec = self._messages_by_id.get(message_id)
        if rec is None:
            raise KeyError("Message not found")
        if rec.status == MessageStatus.BURNED:
            return {"burned": True}
        return {
            "message_id": rec.message_id,
            "direction": rec.direction,
            "required_role": rec.required_role.value,
            "status": rec.status.value,
            "latency_ms": round(rec.latency_ms, 2),
            "decode_confidence": round(rec.decode_confidence, 4),
            "native_engine": native_version(),
            **rec.inspector,
        }

    async def send_typing(self, typing: bool) -> None:
        if self._ws and self.path_id and self.handshake_complete:
            try:
                await self._ws.send(
                    json.dumps(
                        {
                            "type": "peer:typing",
                            "path_id": self.path_id,
                            "payload": {"typing": bool(typing)},
                        }
                    )
                )
            except Exception:
                pass

    async def _self_destruct_loop(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            now = time.time()
            for rec in list(self.messages):
                if (
                    rec.expires_at is not None
                    and rec.status != MessageStatus.BURNED
                    and now >= rec.expires_at
                ):
                    rec.status = MessageStatus.BURNED
                    rec.text = None
                    rec.vault_title = None
                    rec.inspector.clear()
                    self._outbound_chunks.pop(rec.message_id, None)
                    await self._broadcast_ui("message:update", rec.to_ui_dict())

    def get_invite_info(self, advertised_relay_url: Optional[str] = None) -> Optional[dict[str, str]]:
        if not self.path_id:
            return None
        relay = (advertised_relay_url or self.relay_url).rstrip("/")
        invite_code = f"sf://{relay.replace('ws://', '').replace('wss://', '').rstrip('/ws')}/{self.path_id}"
        return {
            "path_id": self.path_id,
            "relay_url": relay,
            "invite_code": invite_code,
            "qr_svg_data_url": _make_qr_svg_data_url(invite_code),
        }

    def get_state_snapshot(self, advertised_relay_url: Optional[str] = None) -> dict[str, Any]:
        return {
            "peer_id": self.peer_id,
            "username": self.username,
            "role": self.role.value,
            "relay_url": self.relay_url,
            "native_engine": native_version(),
            "public_key_fingerprint": self.keypair.public_key_b64[:24] + "...",
            "path_id": self.path_id,
            "is_creator": self.is_creator,
            "connection_status": self.connection_status,
            "handshake_complete": self.handshake_complete,
            "safety_number": self.keyring.safety_number if self.keyring else None,
            "peer_username": self.peer_username,
            "peer_role": self.peer_role,
            "peer_online": self.peer_online,
            "peer_typing": self.peer_typing,
            "invite": self.get_invite_info(advertised_relay_url),
            "messages": [m.to_ui_dict() for m in self.messages],
        }


def parse_invite_input(raw_input: str) -> tuple[str, Optional[str]]:
    """
    Parse either a raw Path ID (`SF-4F9A-8C21-B7D3`) or a full Invite Code
    (`sf://192.168.1.42:8765/SF-4F9A-8C21-B7D3`) so joining takes 1 paste!
    """
    text = raw_input.strip()
    if text.startswith("sf://"):
        body = text[len("sf://") :]
        if "/" in body:
            host_port, path_id = body.rsplit("/", 1)
            scheme = "wss" if ":443" in host_port else "ws"
            return path_id.strip(), f"{scheme}://{host_port.strip()}"
    return text, None
