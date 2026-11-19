# SecureFast — Intelligent Secure Data Storage with Role-Based Decryption

> **Zero-Knowledge End-to-End Encrypted Messaging & Role-Gated Vault**  
> Powered by **Python (FastAPI + WebSockets + NIST Cryptography)** + **C11 Native High-Speed Core (`native/securefast_core.c`)**

Built for **Project Based Learning (CSE, Batch 2025–2029, Section F — Delhi Technical Campus)** by **Akshit Panwar**, **Divyansh Sharma**, and **Dwij Jalali**.

---

## Why Python + C11?

| Layer | Language | What It Does |
|---|---|---|
| **Fast Native Core** | **C11** (`native/securefast_core.c`) | Bare-metal FIPS 180-4 SHA-256, RFC 5869 HKDF-SHA256, BCH(15,7,5) Key-Derived Secret Glyph Alphabet Renderer, Pixel-Only Visual Glyph Decoder, and Constant-Time Memory Scrubbing (`sf_secure_zero`). Renders & decodes 500-char messages in **~20–80 ms** (25×–100× faster than the 2 s target). |
| **Application, Crypto & Relay** | **Python 3.11+** (`FastAPI`, `uvicorn`, `cryptography`, `websockets`, `segno`) | NIST ECDH P-256 key agreement, AES-256-GCM authenticated encryption, Role-Based Decryption (`ADMIN` / `MEMBER` / `GUEST`), Zero-Knowledge Path Relay (`<= 2 KB` chunks, in-memory only), QR invites, and Local Device PWA Web Server. |
| **Installable PWA UI** | **HTML5 / CSS3 / Vanilla JS** (zero external CDNs) | WhatsApp/Telegram-inspired dark & light theme chat + Role-Gated Secure Vault, Tap-to-Reveal, 30-digit Safety Number modal, **5 Forms Pipeline Inspector**, **Zero-Knowledge Relay Proof**, Self-Destruct timers, and Privacy Shield auto-blur. |

---

## Quick Start: Install & Use With Your Friend (First Time!)

### Requirements
- **Python 3.11+** ([python.org/downloads](https://www.python.org/downloads/) — check **"Add Python to PATH"** on Windows)
- That's it! The C11 native engine ships precompiled for Windows (`securefast_core.dll`) AND auto-compiles cleanly on Windows/Linux/macOS using the bundled `ziglang` C11 compiler (no Visual Studio or MinGW required).

---

### Step 1 — Install (Both You and Your Friend)

**Windows (1-click):**
1. Extract or clone the `securefast` folder.
2. Double-click **`setup.bat`**.

**macOS / Linux:**
```bash
chmod +x setup.sh
./setup.sh
```

**Or via `pip` directly:**
```bash
pip install -r requirements.txt
pip install -e . --no-build-isolation --no-deps
python build_native.py
```

---

### Step 2 — Chat With Your Friend (Same Wi-Fi / College LAN / Mobile Hotspot)

#### On **Your Laptop** (Host):
1. Double-click **`start.bat`** (or run `securefast start`).
2. Your browser opens automatically at `http://127.0.0.1:8000`.
3. In the left sidebar:
   - Enter your **Display Name** (e.g. `Divyansh`), select your role (`ADMIN`), and click **Save Identity & Device Keys**.
   - Click **✨ Create New Private Path**.
4. Copy the **One-Paste Friend Invite Code** (looks like `sf://192.168.1.42:8765/SF-XXXX-XXXX-XXXX`) and send it to your friend (or let them scan the QR code).
   > **Windows Firewall note:** The first time you run `start.bat`, Windows Firewall may ask to allow Python on Private networks — click **Allow** so your friend on the same Wi-Fi can reach port `8765`.

#### On **Your Friend's Laptop**:
1. Double-click **`start-friend.bat`** (or run `securefast client`).
2. Their browser opens at `http://127.0.0.1:8000` (all crypto & C11 glyph decoding runs locally on their own machine!).
3. Enter their **Display Name**, choose their role (`ADMIN`, `MEMBER`, or `GUEST`), and click **Save Identity**.
4. Paste your **Invite Code** (`sf://...`) into **Join Friend's Path** and click **Join**.
5. **ECDH P-256 Handshake completes automatically!**
6. Click **🔐 Safety Number** on both laptops and confirm the 30-digit numbers match — you are now chatting end-to-end encrypted with C11 Anti-OCR Secret Glyphs!

---

### Step 3 — Try Role-Based Decryption & 1-Click Local Demo (Great for Viva!)

Want to test both sides on **one single laptop** right now?
- Double-click **`start-demo.bat`** (or run `securefast demo`).
- It launches:
  - **Zero-Knowledge Relay** on `ws://127.0.0.1:8765/ws`
  - **Alice (`ADMIN`)** on `http://127.0.0.1:8001`
  - **Bob (`MEMBER`)** on `http://127.0.0.1:8002`
- Create a path on Alice, paste the Invite Code into Bob, then:
  1. Send a `MEMBER` message → Bob receives it locked (`🔒 Tap to Reveal`) with secret glyph thumbnails; tapping reveals it and turns Alice's ticks green (`✓✓ Read`).
  2. Click **🔍 5 Forms** on any message to inspect the tokens, live C11 secret glyph PNGs, AES-256-GCM IV/ciphertext, and `≤ 2 KB` SHA-256 chunks!
  3. Send an **`ADMIN ONLY`** message (or Vault secret) → Bob (`MEMBER`) mathematically **cannot decrypt it** and sees the **🛡️ Role-Based Decryption Denied** card!
  4. Click **📡 Relay Proof** to prove `Messages Decrypted by Server: 0` and `Disk Writes: 0`!

---

### Chatting Over the Internet (Different Cities / Networks)

Run the standalone Zero-Knowledge Relay on any free cloud host (Render / Railway / Fly.io) or expose port `8765` via a tunnel (e.g. `cloudflared tunnel --url http://127.0.0.1:8765` or `ngrok http 8765`):

```bash
# On the server host:
securefast relay --host 0.0.0.0 --port 8765
```

Then both friends simply put `wss://<your-relay-host>` into **Path Relay URL** in their local SecureFast app!

---

## Automated Tests & Benchmarks (Table 6.1 Verification)

Run the full automated test suite:
```bash
pytest
```

Run the live Table 6.1 speed & 1,000-token accuracy benchmark:
```bash
securefast benchmark
```

Run the standalone bare-metal C11 benchmark:
```bash
python build_native.py --bench
./securefast/native_bin/bench_c.exe   # (or ./securefast/native_bin/bench_c on Linux/macOS)
```

| Quality Target (Report Table 6.1) | Target | Verified By |
|---|---|---|
| Round-trip accuracy over 1,000 random tokens | 100% | `tests/test_glyph_and_anti_ocr.py` & `securefast benchmark` |
| Delivery time for 500-character message | < 2 s | `tests/test_end_to_end_and_perf.py` (~50–150 ms end-to-end!) |
| Plaintext leaks in relay, network, or storage | 0 | `tests/test_relay_zero_knowledge.py` & `tests/test_end_to_end_and_perf.py` |
| Tampered chunk detection | Rejected | SHA-256 (C11) + AES-256-GCM tag (`tests/test_chunking_reliability.py`) |
| Wrong key / wrong glyph seed | Fails | `tests/test_crypto_and_rbac.py` & `tests/test_native_c_engine.py` |
| Role-Based Decryption (`ADMIN` / `MEMBER` / `GUEST`) | Enforced | `tests/test_crypto_and_rbac.py` & E2E test |
| Out-of-order, duplicates, missing chunk resend | Recovered | `tests/test_chunking_reliability.py` |
