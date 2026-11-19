"""
SecureFast "The Path" — Zero-Knowledge In-Memory Relay Server.

Architectural guarantees (matching SecureFast Report Section 3.3 & Slide 15):
  - Zero-knowledge: NEVER decrypts, parses, logs, or writes message content to disk
  - Strictly 1:1 ephemeral paths (max 2 peers per pathId)
  - Hard 2048-byte (2 KB) ciphertext limit enforced on every chunk
  - Automatic path expiration (default 15 minutes) + 24-hour in-memory offline queue
  - Security headers (Helmet-equivalent), CORS allow-list, Pydantic validation,
    and sliding-window rate limiting
"""

from __future__ import annotations

import asyncio
import base64
import secrets
import time
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Optional

from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from securefast import __version__
from securefast.config import RelayConfig
from securefast.models import (
    ChunkAckPayload,
    ChunkResendRequest,
    EncryptedChunkPayload,
    HandshakeInitPayload,
    HandshakeResponsePayload,
    PathStatus,
    RelayEnvelope,
)


@dataclass
class PeerSlot:
    peer_id: str
    username: str = "peer"
    role: str = "MEMBER"
    websocket: Optional[WebSocket] = None
    connected: bool = False
    last_seen: float = field(default_factory=time.time)


@dataclass
class QueuedFrame:
    frame: dict[str, Any]
    queued_at: float = field(default_factory=time.time)


@dataclass
class EphemeralPathRoom:
    path_id: str
    created_at: float
    expires_at: float
    status: PathStatus = PathStatus.WAITING
    peers: dict[str, PeerSlot] = field(default_factory=dict)  # max 2 entries
    offline_queues: dict[str, deque[QueuedFrame]] = field(default_factory=dict)
    last_handshake_init: Optional[dict[str, Any]] = None
    last_handshake_response: Optional[dict[str, Any]] = None
    chunks_relayed: int = 0

    def other_peer(self, peer_id: str) -> Optional[PeerSlot]:
        for pid, slot in self.peers.items():
            if pid != peer_id:
                return slot
        return None


class SlidingWindowRateLimiter:
    """In-memory sliding-window rate limiter per client key."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds
        bucket = self._hits.setdefault(key, deque())
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= self.max_requests:
            return False
        bucket.append(now)
        return True


class ZeroKnowledgeRelayState:
    """Strictly in-memory state — zero database, zero disk persistence, zero plaintext."""

    def __init__(self, config: RelayConfig) -> None:
        self.config = config
        self.paths: dict[str, EphemeralPathRoom] = {}
        self.rate_limiter = SlidingWindowRateLimiter(
            config.rate_limit_max_requests, config.rate_limit_window_seconds
        )
        self.started_at = time.time()
        self.total_chunks_relayed = 0
        self.total_ciphertext_bytes = 0
        self.recent_audit_entries: deque[dict[str, Any]] = deque(maxlen=25)

    def purge_expired(self) -> int:
        now = time.time()
        removed = 0
        expired_ids = [
            pid
            for pid, room in self.paths.items()
            if room.expires_at <= now
            and not any(p.connected for p in room.peers.values())
            and not any(len(q) > 0 for q in room.offline_queues.values())
        ]
        for pid in expired_ids:
            self.paths.pop(pid, None)
            removed += 1

        # Purge expired offline queue items (> 24 h)
        q_cutoff = now - self.config.offline_queue_ttl_seconds
        for room in list(self.paths.values()):
            for q in room.offline_queues.values():
                while q and q[0].queued_at < q_cutoff:
                    q.popleft()
        return removed

    def stats(self) -> dict[str, Any]:
        self.purge_expired()
        active_peers = sum(
            1 for room in self.paths.values() for p in room.peers.values() if p.connected
        )
        queued_chunks = sum(
            len(q) for room in self.paths.values() for q in room.offline_queues.values()
        )
        return {
            "service": "SecureFast Zero-Knowledge Relay (The Path)",
            "version": __version__,
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "active_paths": len(self.paths),
            "connected_peers": active_peers,
            "queued_offline_chunks": queued_chunks,
            "total_chunks_relayed": self.total_chunks_relayed,
            "total_ciphertext_bytes": self.total_ciphertext_bytes,
            "messages_decrypted_by_server": 0,
            "disk_writes": 0,
            "max_chunk_bytes": self.config.max_chunk_bytes,
            "recent_opaque_chunks": list(self.recent_audit_entries),
        }


def _generate_path_id() -> str:
    # Human-friendly high-entropy path code (e.g. SF-4F9A-8C21-B7D3)
    raw = secrets.token_hex(6).upper()
    return f"SF-{raw[0:4]}-{raw[4:8]}-{raw[8:12]}"


async def _safe_send(ws: WebSocket, data: dict[str, Any]) -> bool:
    try:
        await ws.send_json(data)
        return True
    except Exception:
        return False


def create_relay_app(config: Optional[RelayConfig] = None) -> FastAPI:
    cfg = config or RelayConfig()
    state = ZeroKnowledgeRelayState(cfg)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        async def reaper() -> None:
            while True:
                await asyncio.sleep(30)
                state.purge_expired()

        task = asyncio.create_task(reaper())
        try:
            yield
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    app = FastAPI(
        title="SecureFast Zero-Knowledge Relay (The Path)",
        version=__version__,
        lifespan=lifespan,
    )
    app.state.relay = state

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def security_headers_and_rate_limit(request: Request, call_next) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        if not state.rate_limiter.allow(f"http:{client_ip}"):
            return Response(
                content='{"detail":"Rate limit exceeded"}',
                status_code=429,
                media_type="application/json",
            )
        response: Response = await call_next(request)
        # Helmet-equivalent security headers (Report Section 3.3 & Slide 15)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "securefast-relay",
            "version": __version__,
            "active_paths": len(state.paths),
            "messages_decrypted_by_server": 0,
        }

    @app.get("/api/relay/stats")
    async def relay_stats() -> dict[str, Any]:
        return state.stats()

    @app.websocket("/ws")
    async def relay_ws(websocket: WebSocket) -> None:
        await websocket.accept()
        client_ip = websocket.client.host if websocket.client else "unknown"
        bound_path_id: Optional[str] = None
        bound_peer_id: Optional[str] = None

        try:
            while True:
                raw_msg = await websocket.receive_json()
                if not state.rate_limiter.allow(f"ws:{client_ip}"):
                    await _safe_send(
                        websocket,
                        {"type": "error", "payload": {"message": "Rate limit exceeded"}},
                    )
                    continue

                try:
                    env = RelayEnvelope.model_validate(raw_msg)
                except ValidationError as exc:
                    await _safe_send(
                        websocket,
                        {
                            "type": "error",
                            "payload": {"message": "Invalid protocol frame", "details": str(exc)},
                        },
                    )
                    continue

                if env.type == "ping":
                    await _safe_send(websocket, {"type": "pong", "payload": {"ts": time.time()}})
                    continue

                # --------------------------------------------------------------
                # 1. Create Ephemeral Path (1:1 Room)
                # --------------------------------------------------------------
                if env.type == "path:create":
                    peer_id = str(env.payload.get("peer_id") or secrets.token_hex(8))
                    username = str(env.payload.get("username") or "Creator")[:40]
                    role = str(env.payload.get("role") or "ADMIN")
                    requested_id = env.path_id or env.payload.get("path_id")
                    path_id = str(requested_id).strip() if requested_id else _generate_path_id()

                    if path_id in state.paths and len(state.paths[path_id].peers) >= 2:
                        await _safe_send(
                            websocket,
                            {"type": "error", "payload": {"message": "Path already exists and is full"}},
                        )
                        continue

                    now = time.time()
                    room = EphemeralPathRoom(
                        path_id=path_id,
                        created_at=now,
                        expires_at=now + cfg.path_ttl_seconds,
                        status=PathStatus.WAITING,
                    )
                    room.peers[peer_id] = PeerSlot(
                        peer_id=peer_id,
                        username=username,
                        role=role,
                        websocket=websocket,
                        connected=True,
                        last_seen=now,
                    )
                    room.offline_queues.setdefault(peer_id, deque())
                    state.paths[path_id] = room
                    bound_path_id = path_id
                    bound_peer_id = peer_id

                    await _safe_send(
                        websocket,
                        {
                            "type": "path:created",
                            "path_id": path_id,
                            "payload": {
                                "path_id": path_id,
                                "peer_id": peer_id,
                                "expires_at": room.expires_at,
                                "status": room.status.value,
                            },
                        },
                    )
                    continue

                # --------------------------------------------------------------
                # 2. Join Existing Path (Enforces strict 1:1 2-peer cap!)
                # --------------------------------------------------------------
                if env.type == "path:join":
                    path_id = str(env.path_id or env.payload.get("path_id") or "").strip()
                    peer_id = str(env.payload.get("peer_id") or secrets.token_hex(8))
                    username = str(env.payload.get("username") or "Receiver")[:40]
                    role = str(env.payload.get("role") or "MEMBER")

                    room = state.paths.get(path_id)
                    if room is None:
                        await _safe_send(
                            websocket,
                            {"type": "error", "payload": {"message": f"Path '{path_id}' not found or expired"}},
                        )
                        continue

                    if peer_id not in room.peers and len(room.peers) >= 2:
                        await _safe_send(
                            websocket,
                            {"type": "error", "payload": {"message": "Path is full (1:1 limit reached)"}},
                        )
                        continue

                    now = time.time()
                    room.expires_at = now + cfg.path_ttl_seconds
                    room.peers[peer_id] = PeerSlot(
                        peer_id=peer_id,
                        username=username,
                        role=role,
                        websocket=websocket,
                        connected=True,
                        last_seen=now,
                    )
                    room.offline_queues.setdefault(peer_id, deque())
                    if len(room.peers) == 2:
                        room.status = PathStatus.ACTIVE

                    bound_path_id = path_id
                    bound_peer_id = peer_id

                    other = room.other_peer(peer_id)
                    await _safe_send(
                        websocket,
                        {
                            "type": "path:joined",
                            "path_id": path_id,
                            "payload": {
                                "path_id": path_id,
                                "peer_id": peer_id,
                                "status": room.status.value,
                                "peer_online": bool(other and other.connected),
                                "peer_username": other.username if other else None,
                                "peer_role": other.role if other else None,
                            },
                        },
                    )

                    # Notify the other peer that their contact joined/reconnected
                    if other and other.connected and other.websocket is not None:
                        await _safe_send(
                            other.websocket,
                            {
                                "type": "path:peer_connected",
                                "path_id": path_id,
                                "payload": {
                                    "peer_id": peer_id,
                                    "username": username,
                                    "role": role,
                                },
                            },
                        )

                    # Replay cached handshake init if the creator already sent one
                    if room.last_handshake_init and room.last_handshake_init.get("peer_id") != peer_id:
                        await _safe_send(
                            websocket,
                            {
                                "type": "handshake:init",
                                "path_id": path_id,
                                "payload": room.last_handshake_init,
                            },
                        )

                    # Flush any offline-queued encrypted chunks held in memory for this peer
                    for q_key in (peer_id, "__pending__"):
                        q = room.offline_queues.get(q_key)
                        if q:
                            q_cutoff = now - cfg.offline_queue_ttl_seconds
                            while q:
                                queued = q.popleft()
                                if queued.queued_at >= q_cutoff:
                                    await _safe_send(websocket, queued.frame)
                    continue

                # All subsequent events require a bound path
                if not bound_path_id or not bound_peer_id or bound_path_id not in state.paths:
                    await _safe_send(
                        websocket,
                        {"type": "error", "payload": {"message": "Not attached to an active path"}},
                    )
                    continue

                room = state.paths[bound_path_id]
                room.expires_at = time.time() + cfg.path_ttl_seconds
                other = room.other_peer(bound_peer_id)

                # --------------------------------------------------------------
                # 3. ECDH Public Key Handshake Relay
                # --------------------------------------------------------------
                if env.type == "handshake:init":
                    try:
                        hs = HandshakeInitPayload.model_validate(env.payload)
                    except ValidationError as exc:
                        await _safe_send(
                            websocket,
                            {"type": "error", "payload": {"message": f"Invalid handshake:init: {exc}"}},
                        )
                        continue
                    data = hs.model_dump()
                    room.last_handshake_init = data
                    if other and other.connected and other.websocket is not None:
                        await _safe_send(
                            other.websocket,
                            {"type": "handshake:init", "path_id": bound_path_id, "payload": data},
                        )
                    continue

                if env.type == "handshake:response":
                    try:
                        hs_r = HandshakeResponsePayload.model_validate(env.payload)
                    except ValidationError as exc:
                        await _safe_send(
                            websocket,
                            {"type": "error", "payload": {"message": f"Invalid handshake:response: {exc}"}},
                        )
                        continue
                    data = hs_r.model_dump()
                    room.last_handshake_response = data
                    if other and other.connected and other.websocket is not None:
                        await _safe_send(
                            other.websocket,
                            {"type": "handshake:response", "path_id": bound_path_id, "payload": data},
                        )
                    continue

                # --------------------------------------------------------------
                # 4. Zero-Knowledge Encrypted Chunk Relay (<= 2 KB strict check)
                # --------------------------------------------------------------
                if env.type == "chunk:send":
                    try:
                        chunk = EncryptedChunkPayload.model_validate(env.payload)
                        raw_ct = base64.b64decode(chunk.ciphertext_b64, validate=True)
                    except Exception as exc:
                        await _safe_send(
                            websocket,
                            {"type": "error", "payload": {"message": f"Invalid chunk payload: {exc}"}},
                        )
                        continue

                    if len(raw_ct) > cfg.max_chunk_bytes:
                        await _safe_send(
                            websocket,
                            {
                                "type": "error",
                                "payload": {
                                    "message": f"Chunk rejected: {len(raw_ct)} B exceeds {cfg.max_chunk_bytes} B limit"
                                },
                            },
                        )
                        continue

                    room.chunks_relayed += 1
                    state.total_chunks_relayed += 1
                    state.total_ciphertext_bytes += len(raw_ct)
                    state.recent_audit_entries.append(
                        {
                            "ts": round(time.time(), 2),
                            "path_id": bound_path_id,
                            "message_id": chunk.message_id,
                            "chunk": f"{chunk.chunk_index + 1}/{chunk.total_chunks}",
                            "ciphertext_bytes": len(raw_ct),
                            "checksum_prefix": chunk.checksum_hex[:16] + "...",
                            "required_role": chunk.required_role.value,
                            "plaintext_visible_to_relay": None,
                        }
                    )

                    outbound = {
                        "type": "chunk:receive",
                        "path_id": bound_path_id,
                        "payload": chunk.model_dump(),
                    }

                    if other and other.connected and other.websocket is not None:
                        await _safe_send(other.websocket, outbound)
                    elif other is not None:
                        # Peer temporarily offline -> hold ciphertext in RAM up to 24 h
                        room.offline_queues.setdefault(other.peer_id, deque()).append(
                            QueuedFrame(frame=outbound)
                        )
                        await _safe_send(
                            websocket,
                            {
                                "type": "chunk:queued_offline",
                                "path_id": bound_path_id,
                                "payload": {
                                    "message_id": chunk.message_id,
                                    "chunk_index": chunk.chunk_index,
                                },
                            },
                        )
                    else:
                        # Second peer hasn't joined yet -> buffer under sentinel key "__pending__"
                        room.offline_queues.setdefault("__pending__", deque()).append(
                            QueuedFrame(frame=outbound)
                        )
                    continue

                # --------------------------------------------------------------
                # 5. Chunk ACK, Resend Request, Read Receipt, Typing Indicator
                # --------------------------------------------------------------
                if env.type == "chunk:ack":
                    try:
                        ack = ChunkAckPayload.model_validate(env.payload)
                    except ValidationError:
                        continue
                    if other and other.connected and other.websocket is not None:
                        await _safe_send(
                            other.websocket,
                            {"type": "chunk:ack", "path_id": bound_path_id, "payload": ack.model_dump()},
                        )
                    continue

                if env.type == "chunk:resend_req":
                    try:
                        req = ChunkResendRequest.model_validate(env.payload)
                    except ValidationError:
                        continue
                    if other and other.connected and other.websocket is not None:
                        await _safe_send(
                            other.websocket,
                            {
                                "type": "chunk:resend_req",
                                "path_id": bound_path_id,
                                "payload": req.model_dump(),
                            },
                        )
                    continue

                if env.type in ("message:read", "peer:typing"):
                    if other and other.connected and other.websocket is not None:
                        await _safe_send(
                            other.websocket,
                            {"type": env.type, "path_id": bound_path_id, "payload": env.payload},
                        )
                    continue

                if env.type == "path:destroy":
                    room.status = PathStatus.DESTROYED
                    if other and other.connected and other.websocket is not None:
                        await _safe_send(
                            other.websocket,
                            {"type": "path:destroyed", "path_id": bound_path_id, "payload": {}},
                        )
                    state.paths.pop(bound_path_id, None)
                    bound_path_id = None
                    continue

        except WebSocketDisconnect:
            pass
        finally:
            if bound_path_id and bound_peer_id and bound_path_id in state.paths:
                room = state.paths[bound_path_id]
                slot = room.peers.get(bound_peer_id)
                if slot is not None:
                    slot.connected = False
                    slot.websocket = None
                    slot.last_seen = time.time()
                other = room.other_peer(bound_peer_id)
                if other and other.connected and other.websocket is not None:
                    await _safe_send(
                        other.websocket,
                        {
                            "type": "path:peer_disconnected",
                            "path_id": bound_path_id,
                            "payload": {"peer_id": bound_peer_id},
                        },
                    )

    return app
