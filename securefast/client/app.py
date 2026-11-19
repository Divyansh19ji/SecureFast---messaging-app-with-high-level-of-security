"""
Local Device Web Application & PWA Server (FastAPI).

Runs locally on each user's machine (`http://127.0.0.1:8000`).
All cryptography, Role-Based Decryption, and C11 Anti-OCR Secret Glyph imaging
execute strictly inside this local Python + C11 process — never on the Relay!
"""

from __future__ import annotations

import socket
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal, Optional
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from securefast import __version__
from securefast.client.session import DeviceSessionManager
from securefast.config import ClientConfig
from securefast.crypto_engine import RoleAccessDeniedError
from securefast.models import Role
from securefast.native_bridge import native_version

STATIC_DIR = Path(__file__).resolve().parent / "static"


def detect_lan_ip() -> str:
    """Detect this machine's LAN IPv4 address for easy Wi-Fi/hotspot friend invites."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
    except Exception:
        pass
    try:
        host_ip = socket.gethostbyname(socket.gethostname())
        if host_ip and not host_ip.startswith("127."):
            return host_ip
    except Exception:
        pass
    return "127.0.0.1"


def compute_advertised_relay_url(relay_url: str, lan_ip: str) -> str:
    parsed = urlparse(relay_url if "://" in relay_url else f"ws://{relay_url}")
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "wss" else 8765)
    scheme = parsed.scheme or "ws"
    if host in ("127.0.0.1", "localhost", "0.0.0.0") and lan_ip != "127.0.0.1":
        return f"{scheme}://{lan_ip}:{port}"
    return f"{scheme}://{host}:{port}"


class IdentityRequest(BaseModel):
    username: str = Field(min_length=1, max_length=40)
    role: Role = Role.ADMIN
    relay_url: Optional[str] = None


class CreatePathRequest(BaseModel):
    relay_url: Optional[str] = None
    custom_path_id: Optional[str] = None


class JoinPathRequest(BaseModel):
    path_id: str = Field(min_length=3, max_length=200)
    relay_url: Optional[str] = None


class SendMessageRequest(BaseModel):
    text: str = Field(min_length=1, max_length=8000)
    required_role: Role = Role.MEMBER
    self_destruct_sec: int = Field(default=0, ge=0, le=86400)
    kind: Literal["chat", "vault"] = "chat"
    vault_title: Optional[str] = Field(default=None, max_length=80)


class TypingRequest(BaseModel):
    typing: bool = False


def create_client_app(config: Optional[ClientConfig] = None) -> FastAPI:
    cfg = config or ClientConfig()
    session = DeviceSessionManager(cfg)
    lan_ip = detect_lan_ip()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        session.start_background_tasks()
        try:
            yield
        finally:
            await session.shutdown()

    app = FastAPI(title="SecureFast Device Client", version=__version__, lifespan=lifespan)
    app.state.session = session
    app.state.lan_ip = lan_ip

    def _adv_relay() -> str:
        return compute_advertised_relay_url(session.relay_url, lan_ip)

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "service": "securefast-client",
            "version": __version__,
            "native_engine": native_version(),
            "lan_ip": lan_ip,
        }

    @app.get("/api/state")
    async def get_state() -> dict[str, Any]:
        snap = session.get_state_snapshot(advertised_relay_url=_adv_relay())
        snap["lan_ip"] = lan_ip
        snap["advertised_relay_url"] = _adv_relay()
        return snap

    @app.post("/api/identity")
    async def set_identity(req: IdentityRequest) -> dict[str, Any]:
        try:
            await session.setup_identity(req.username, req.role, req.relay_url)
            snap = session.get_state_snapshot(advertised_relay_url=_adv_relay())
            snap["lan_ip"] = lan_ip
            snap["advertised_relay_url"] = _adv_relay()
            return snap
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/path/create")
    async def create_path(req: CreatePathRequest) -> dict[str, Any]:
        try:
            await session.create_path(relay_url=req.relay_url, custom_path_id=req.custom_path_id)
            snap = session.get_state_snapshot(advertised_relay_url=_adv_relay())
            snap["lan_ip"] = lan_ip
            snap["advertised_relay_url"] = _adv_relay()
            return snap
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/path/join")
    async def join_path(req: JoinPathRequest) -> dict[str, Any]:
        try:
            await session.join_path(path_id=req.path_id, relay_url=req.relay_url)
            snap = session.get_state_snapshot(advertised_relay_url=_adv_relay())
            snap["lan_ip"] = lan_ip
            snap["advertised_relay_url"] = _adv_relay()
            return snap
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/path/leave")
    async def leave_path(destroy: bool = False) -> dict[str, Any]:
        await session.disconnect(notify_relay=destroy)
        snap = session.get_state_snapshot(advertised_relay_url=_adv_relay())
        snap["lan_ip"] = lan_ip
        snap["advertised_relay_url"] = _adv_relay()
        return snap

    @app.post("/api/messages/send")
    async def send_message(req: SendMessageRequest) -> dict[str, Any]:
        try:
            return await session.send_message(
                text=req.text,
                required_role=req.required_role,
                self_destruct_sec=req.self_destruct_sec,
                kind=req.kind,
                vault_title=req.vault_title,
            )
        except RoleAccessDeniedError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/messages/{message_id}/reveal")
    async def reveal_message(message_id: str) -> dict[str, Any]:
        try:
            return await session.reveal_message(message_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Message not found") from exc
        except RoleAccessDeniedError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.get("/api/messages/{message_id}/inspect")
    async def inspect_message(message_id: str) -> dict[str, Any]:
        try:
            return session.get_inspector(message_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Message not found") from exc

    @app.post("/api/typing")
    async def set_typing(req: TypingRequest) -> dict[str, str]:
        await session.send_typing(req.typing)
        return {"status": "ok"}

    @app.get("/api/relay/audit")
    async def relay_audit() -> JSONResponse:
        """Fetch live zero-knowledge stats from the connected Relay to prove 0 plaintext on server."""
        raw = session.relay_url.strip()
        http_url = raw.replace("wss://", "https://").replace("ws://", "http://").rstrip("/")
        if http_url.endswith("/ws"):
            http_url = http_url[:-3]
        try:
            async with httpx.AsyncClient(timeout=2.5) as client:
                resp = await client.get(f"{http_url}/api/relay/stats")
                return JSONResponse(status_code=resp.status_code, content=resp.json())
        except Exception as exc:
            return JSONResponse(
                status_code=503,
                content={"error": f"Relay unreachable at {http_url}: {exc}"},
            )

    @app.websocket("/ws/ui")
    async def ui_events(websocket: WebSocket) -> None:
        await websocket.accept()
        q = session.subscribe_ui()
        try:
            snap = session.get_state_snapshot(advertised_relay_url=_adv_relay())
            snap["lan_ip"] = lan_ip
            snap["advertised_relay_url"] = _adv_relay()
            await websocket.send_json({"type": "state", "data": snap})
            while True:
                event = await q.get()
                if event["type"] == "state":
                    event["data"]["lan_ip"] = lan_ip
                    event["data"]["advertised_relay_url"] = _adv_relay()
                    event["data"]["invite"] = session.get_invite_info(_adv_relay())
                await websocket.send_json(event)
        except WebSocketDisconnect:
            pass
        finally:
            session.unsubscribe_ui(q)

    # PWA files served cleanly at root
    @app.get("/manifest.json")
    async def manifest() -> FileResponse:
        return FileResponse(STATIC_DIR / "manifest.json", media_type="application/manifest+json")

    @app.get("/sw.js")
    async def service_worker() -> FileResponse:
        return FileResponse(STATIC_DIR / "sw.js", media_type="application/javascript")

    @app.get("/icon.svg")
    async def icon_svg() -> FileResponse:
        return FileResponse(STATIC_DIR / "icon.svg", media_type="image/svg+xml")

    @app.get("/")
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    return app
