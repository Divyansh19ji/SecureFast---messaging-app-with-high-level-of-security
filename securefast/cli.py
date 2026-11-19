"""
SecureFast Unified Command-Line Interface.

Commands:
  securefast start      Start Relay + Local Device App together (Host friend / solo start)
  securefast client     Start Local Device App only (Joining friend)
  securefast relay      Start Zero-Knowledge Relay Server ("The Path") only (Hosting)
  securefast demo       Start Relay + Alice (:8001) + Bob (:8002) for 1-click two-user demo
  securefast benchmark  Run Table 6.1 performance & accuracy benchmarks (Python + C11)
  securefast build      Compile the C11 native engine (`native/securefast_core.c`)
"""

from __future__ import annotations

import argparse
import asyncio
import secrets
import string
import sys
import time
import webbrowser
from pathlib import Path

import uvicorn

from securefast import __version__
from securefast.chunk_engine import ChunkReassemblyBuffer, encrypt_and_chunk_bundle
from securefast.client.app import create_client_app, detect_lan_ip
from securefast.config import ClientConfig, RelayConfig
from securefast.crypto_engine import DeviceKeyPair, SessionKeyring, generate_salt
from securefast.glyph_engine import (
    decode_glyph_bundle,
    encode_text_to_glyph_tokens,
    pack_glyph_bundle,
)
from securefast.models import Role
from securefast.native_bridge import GlyphDecodeError, native_version
from securefast.relay.app import create_relay_app


async def _serve_app(app, host: str, port: int) -> None:
    config = uvicorn.Config(app=app, host=host, port=port, log_level="warning")
    server = uvicorn.Server(config)
    await server.serve()


async def _open_browser_later(urls: list[str], delay: float = 1.1) -> None:
    await asyncio.sleep(delay)
    for url in urls:
        try:
            webbrowser.open(url)
        except Exception:
            pass


async def _run_start(args: argparse.Namespace) -> None:
    lan_ip = detect_lan_ip()
    relay_cfg = RelayConfig(host="0.0.0.0", port=args.relay_port)
    client_cfg = ClientConfig(
        host="127.0.0.1",
        port=args.client_port,
        relay_url=f"ws://127.0.0.1:{args.relay_port}",
        default_username=args.name or "",
        default_role=args.role,
    )

    relay_app = create_relay_app(relay_cfg)
    client_app = create_client_app(client_cfg)

    print("=" * 64)
    print(f"  SecureFast v{__version__}  |  Engine: {native_version()}")
    print("=" * 64)
    print(f"  Your Local App    : http://127.0.0.1:{args.client_port}")
    print(f"  Local Path Relay  : ws://127.0.0.1:{args.relay_port}/ws")
    print(f"  Friend LAN Relay  : ws://{lan_ip}:{args.relay_port}/ws")
    print("-" * 64)
    print("  1) Open your Local App and click 'Create New Private Path'.")
    print("  2) Copy the Invite Code (starts with sf://...) and send it to")
    print("     your friend on the same Wi-Fi (or paste into their app).")
    print("  Press Ctrl+C to stop.")
    print("=" * 64)

    tasks = [
        asyncio.create_task(_serve_app(relay_app, "0.0.0.0", args.relay_port)),
        asyncio.create_task(_serve_app(client_app, "127.0.0.1", args.client_port)),
    ]
    if not args.no_browser:
        tasks.append(
            asyncio.create_task(_open_browser_later([f"http://127.0.0.1:{args.client_port}"]))
        )
    await asyncio.gather(*tasks)


async def _run_client(args: argparse.Namespace) -> None:
    client_cfg = ClientConfig(
        host="127.0.0.1",
        port=args.port,
        relay_url=args.relay,
        default_username=args.name or "",
        default_role=args.role,
    )
    client_app = create_client_app(client_cfg)

    print("=" * 64)
    print(f"  SecureFast Friend Client v{__version__}  |  {native_version()}")
    print("=" * 64)
    print(f"  Your Local App : http://127.0.0.1:{args.port}")
    print(f"  Target Relay   : {args.relay}")
    print("  Paste your friend's Invite Code (sf://...) into 'Join Friend's Path'.")
    print("  Press Ctrl+C to stop.")
    print("=" * 64)

    tasks = [asyncio.create_task(_serve_app(client_app, "127.0.0.1", args.port))]
    if not args.no_browser:
        tasks.append(asyncio.create_task(_open_browser_later([f"http://127.0.0.1:{args.port}"])))
    await asyncio.gather(*tasks)


async def _run_relay(args: argparse.Namespace) -> None:
    lan_ip = detect_lan_ip()
    relay_cfg = RelayConfig(host=args.host, port=args.port)
    relay_app = create_relay_app(relay_cfg)

    print("=" * 64)
    print(f"  SecureFast Zero-Knowledge Relay ('The Path') v{__version__}")
    print("=" * 64)
    print(f"  Listening : ws://{args.host}:{args.port}/ws")
    print(f"  LAN URL   : ws://{lan_ip}:{args.port}/ws")
    print(f"  Health    : http://127.0.0.1:{args.port}/health")
    print("  Zero-knowledge mode: 0 plaintext decrypted, 0 disk writes.")
    print("=" * 64)

    await _serve_app(relay_app, args.host, args.port)


async def _run_demo(args: argparse.Namespace) -> None:
    relay_app = create_relay_app(RelayConfig(host="127.0.0.1", port=args.relay_port))
    alice_app = create_client_app(
        ClientConfig(
            host="127.0.0.1",
            port=8001,
            relay_url=f"ws://127.0.0.1:{args.relay_port}",
            default_username="Alice",
            default_role="ADMIN",
        )
    )
    bob_app = create_client_app(
        ClientConfig(
            host="127.0.0.1",
            port=8002,
            relay_url=f"ws://127.0.0.1:{args.relay_port}",
            default_username="Bob",
            default_role="MEMBER",
        )
    )

    print("=" * 64)
    print(f"  SecureFast 2-User Live Demo v{__version__}  |  {native_version()}")
    print("=" * 64)
    print(f"  Zero-Knowledge Relay : ws://127.0.0.1:{args.relay_port}/ws")
    print("  Alice (ADMIN)        : http://127.0.0.1:8001")
    print("  Bob   (MEMBER)       : http://127.0.0.1:8002")
    print("-" * 64)
    print("  Tip: On Alice (:8001), click 'Create New Private Path' and copy")
    print("       the Invite Code into Bob (:8002). Try sending an ADMIN-only")
    print("       message to watch Role-Based Decryption lock it on Bob!")
    print("=" * 64)

    tasks = [
        asyncio.create_task(_serve_app(relay_app, "127.0.0.1", args.relay_port)),
        asyncio.create_task(_serve_app(alice_app, "127.0.0.1", 8001)),
        asyncio.create_task(_serve_app(bob_app, "127.0.0.1", 8002)),
    ]
    if not args.no_browser:
        tasks.append(
            asyncio.create_task(
                _open_browser_later(["http://127.0.0.1:8001", "http://127.0.0.1:8002"])
            )
        )
    await asyncio.gather(*tasks)


def _run_benchmark() -> None:
    print("=" * 64)
    print(f"  SecureFast Quality & Performance Benchmark ({native_version()})")
    print("=" * 64)

    # 1. Establish ECDH P-256 + HKDF keys
    kp_a = DeviceKeyPair.generate()
    kp_b = DeviceKeyPair.generate()
    salt = generate_salt()
    kr_a = SessionKeyring.establish(kp_a, kp_b.public_key_b64, salt, Role.ADMIN)
    kr_b = SessionKeyring.establish(kp_b, kp_a.public_key_b64, salt, Role.ADMIN)
    assert kr_a.safety_number == kr_b.safety_number
    seed = bytes(kr_a.get_role_material(Role.MEMBER).glyph_seed)

    # 2. 1000 random tokens round-trip accuracy (Table 6.1 target: 100%)
    chars = string.ascii_letters + string.digits + "!@#$%&*()-_=+."
    rng_tokens = [
        "".join(secrets.choice(chars) for _ in range(secrets.randbelow(10) + 1))
        for _ in range(1000)
    ]
    t0 = time.perf_counter()
    passed = 0
    for tok in rng_tokens:
        _, rendered = encode_text_to_glyph_tokens(tok, seed)
        bundle = pack_glyph_bundle(rendered)
        decoded = decode_glyph_bundle(bundle, seed)
        if decoded.text == tok:
            passed += 1
    t_1000 = (time.perf_counter() - t0) * 1000.0

    # 3. 500-character full pipeline latency (Table 6.1 target: < 2000 ms)
    msg_500 = (
        "Confidential Q4 merger memo: Project SecureFast closes Friday at $42.5M. "
        "Verify wire routing #99201-AX and safety number before releasing escrow! "
    ) * 4
    msg_500 = msg_500[:500]
    t1 = time.perf_counter()
    _, g_tokens = encode_text_to_glyph_tokens(msg_500, seed)
    bundle_500 = pack_glyph_bundle(g_tokens)
    chunks = encrypt_and_chunk_bundle(bundle_500, "SF-BENCH", "msg-500", kr_a, Role.MEMBER)
    buf = ChunkReassemblyBuffer("msg-500", "SF-BENCH", len(chunks), Role.MEMBER)
    for c in reversed(chunks):  # Out-of-order test!
        buf.add_chunk(c)
    dec_bundle = buf.decrypt_and_reassemble(kr_b)
    dec_msg = decode_glyph_bundle(dec_bundle, seed)
    t_500 = (time.perf_counter() - t1) * 1000.0
    assert dec_msg.text == msg_500

    # 4. Wrong seed check
    wrong_seed = bytes([seed[0] ^ 0xFF]) + seed[1:]
    wrong_rejected = False
    try:
        decode_glyph_bundle(dec_bundle, wrong_seed)
    except GlyphDecodeError:
        wrong_rejected = True

    print(f"  Safety Number Match       : PASS ({kr_a.safety_number})")
    print(f"  1000 Random Tokens        : {passed}/1000 ({passed/10:.2f}%) in {t_1000:.1f} ms")
    print(f"  500-Char Full E2EE+Glyph  : {t_500:.1f} ms ({len(chunks)} chunks <= 2 KB) [Target < 2000 ms]")
    print(f"  Out-of-Order Reassembly   : PASS (reversed {len(chunks)} chunks)")
    print(f"  Wrong Glyph Seed Rejected : {'PASS' if wrong_rejected else 'FAIL'}")
    print("=" * 64)


def _run_build() -> None:
    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    import build_native

    build_native.build_shared_library(build_bench=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="securefast",
        description="SecureFast — Zero-Knowledge Anti-OCR Messaging & RBAC Vault (Python + C11)",
    )
    sub = parser.add_subparsers(dest="command")

    p_start = sub.add_parser("start", help="Start Relay + Local Device App (1-click host mode)")
    p_start.add_argument("--name", default="", help="Initial display name")
    p_start.add_argument("--role", default="ADMIN", choices=["ADMIN", "MEMBER", "GUEST"])
    p_start.add_argument("--relay-port", type=int, default=8765)
    p_start.add_argument("--client-port", type=int, default=8000)
    p_start.add_argument("--no-browser", action="store_true")

    p_client = sub.add_parser("client", help="Start Local Device App only (join a friend's relay)")
    p_client.add_argument("--relay", default="ws://127.0.0.1:8765", help="Relay WebSocket URL")
    p_client.add_argument("--name", default="", help="Initial display name")
    p_client.add_argument("--role", default="MEMBER", choices=["ADMIN", "MEMBER", "GUEST"])
    p_client.add_argument("--port", type=int, default=8000)
    p_client.add_argument("--no-browser", action="store_true")

    p_relay = sub.add_parser("relay", help="Start standalone Zero-Knowledge Relay ('The Path')")
    p_relay.add_argument("--host", default="0.0.0.0")
    p_relay.add_argument("--port", type=int, default=8765)

    p_demo = sub.add_parser("demo", help="Start Relay + Alice (:8001) + Bob (:8002) local demo")
    p_demo.add_argument("--relay-port", type=int, default=8765)
    p_demo.add_argument("--no-browser", action="store_true")

    sub.add_parser("benchmark", help="Run Table 6.1 accuracy and speed benchmarks")
    sub.add_parser("build", help="Compile the C11 native engine")

    args = parser.parse_args()
    if args.command is None:
        # Default to `start` when invoked with no subcommand
        args = parser.parse_args(["start"])

    try:
        if args.command == "start":
            asyncio.run(_run_start(args))
        elif args.command == "client":
            asyncio.run(_run_client(args))
        elif args.command == "relay":
            asyncio.run(_run_relay(args))
        elif args.command == "demo":
            asyncio.run(_run_demo(args))
        elif args.command == "benchmark":
            _run_benchmark()
        elif args.command == "build":
            _run_build()
    except KeyboardInterrupt:
        print("\nSecureFast stopped cleanly. All ephemeral memory scrubbed.")


if __name__ == "__main__":
    main()
