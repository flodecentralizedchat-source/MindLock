# MindLock — Autonomous Data Security System

A complete, production-ready secure file system built in Rust. Files that think, defend themselves, deceive attackers, self-destruct, and integrate with Web3.

---

## Architecture

```
mindlock/
├── core/          Rust library — all cryptographic primitives & logic
│   ├── crypto.rs    AES-256-GCM + Argon2id + HMAC + device fingerprinting
│   ├── format.rs    .mindlock binary file format (magic + header + payload)
│   ├── rules.rs     Access policy engine (time-lock, device trust, open limits)
│   ├── behavior.rs  Keystroke dynamics — z-score + DTW anomaly detection
│   ├── decoy.rs     Decoy content generation + per-recipient watermarking
│   └── wipe.rs      DoD 5220.22-M 3-pass secure erase
├── cli/           mindlock binary — lock, unlock, inspect, wipe, enroll
├── daemon/        mindlockd — Phase 3 REST backend (Axum + PostgreSQL)
│   ├── routes.rs    Full REST API with access check + remote revoke + log
│   └── db.rs        SQLx database layer with auto-migration
├── web3/          Phase 4 — wallet auth, ERC-20 gate, pay-to-open, chain log
│   ├── wallet.rs    EIP-191 personal_sign verification
│   ├── token.rs     ERC-20/ERC-721 balance via raw JSON-RPC
│   ├── payment.rs   Pay-to-open invoice + tx verification
│   └── chain_log.rs Immutable on-chain access log
└── dashboard/     Phase 3 remote control web UI (HTML/JS — zero dependencies)
```

---

## The .mindlock File Format

```
[0..4]    Magic    : 0x4D 0x4C 0x4B 0x21  ("MLK!")
[4]       Version  : u8
[5..9]    HdrLen   : u32 (big-endian)
[9..N]    Header   : JSON (MindLockHeader — rules, policy, metadata)
[N..N+8]  PayLen   : u64 (big-endian)
[N+8..]   Payload  : bincode-encoded EncryptedBlob
           └─ nonce (12 bytes AES-GCM)
           └─ ciphertext (AES-256-GCM authenticated)
           └─ salt (32 bytes Argon2id)
           └─ hmac (HMAC-SHA256 over salt+nonce+ciphertext)
[..]      DecoyLen : u64 (0 if no decoy)
[..]      Decoy    : optional second EncryptedBlob (same format)
```

Header is plaintext JSON so policies can be read and evaluated **before** any decryption attempt.

---

## Crypto Stack

| Concern            | Algorithm             | Why                              |
|--------------------|-----------------------|----------------------------------|
| Key derivation     | Argon2id (64MB, 3i, 4p) | Memory-hard, side-channel resistant |
| Symmetric enc      | AES-256-GCM           | AEAD — confidentiality + integrity  |
| Integrity (extra)  | HMAC-SHA-256          | Fail-fast before GCM              |
| Key exchange       | RSA-4096 OAEP/SHA-256 | Optional key wrapping             |
| Device ID          | SHA-256(hostname+user+os+arch) | Stable, cross-platform    |
| Watermarking       | Zero-width unicode (U+200B/U+200C) | Invisible in text viewers |
| Behavior hash      | SHA-256(baseline JSON) | Tamper-evident profile storage   |

---

## Phases

### MVP (Phase 1) — Core lock + unlock
- `.mindlock` binary format with AES-256-GCM + Argon2id
- Time-lock (expire after date)
- Open-count limit (max N opens)
- CLI: `lock`, `unlock`, `inspect`, `status`

### Phase 2 — Active defense
- Device fingerprinting — lock to trusted machines
- **Decoy mode** — wrong access → convincing fake file, real stays hidden
- **Self-destruct** — DoD 3-pass wipe after N failed attempts
- Rules engine with IF/THEN policy logic
- Per-recipient watermarked decoys (invisible unicode tags)
- CLI: `wipe`, `adddevice`, `rekey`

### Phase 3 — Remote control
- `mindlockd` daemon — Axum REST server + PostgreSQL
- Remote revoke (takes effect globally, instantly)
- Remote policy update — change rules without re-sharing the file
- Full access log — every open, deny, decoy event logged with device + IP
- **Behavior-based AI (v1)** — keystroke dynamics baseline enrollment
  - z-score anomaly detection (rule-based, no ML training data required)
  - DTW-based similarity as Phase 4 prep
- CLI: `enroll`
- Web dashboard — file table, live access log, revoke/wipe controls

### Phase 4 — Web3 + ML
- **Token-gate** — ERC-20/ERC-721 balance check via raw JSON-RPC
- **Pay-to-open** — ETH micro-payment invoice + on-chain tx verification
- **Blockchain access log** — immutable event history via smart contract
- **Multi-person unlock** — Shamir Secret Sharing (M-of-N keyholders)
- **AI behavior model (v2)** — DTW distance replaces z-score thresholds
- Wallet challenge/response — EIP-191 personal_sign verification
- toklo.xyz DWT token integration (plug in your contract address + chain ID)

---

## Quick Start

### Prerequisites
- Rust 1.78+ (`rustup update stable`)
- PostgreSQL 14+ (for Phase 3 daemon)

### Build everything
```bash
cargo build --release
```

### CLI — Phase 1 (MVP)
```bash
# Lock a file
./target/release/mindlock lock report.pdf \
  --label "Q3 Report" \
  --max-opens 10 \
  --expires 2025-12-31

# Unlock
./target/release/mindlock unlock report.pdf.mindlock

# Inspect (no password needed)
./target/release/mindlock inspect report.pdf.mindlock

# Status
./target/release/mindlock status report.pdf.mindlock
```

### Phase 2 — Decoy + self-destruct
```bash
# Lock with decoy mode + 3-attempt self-destruct
./target/release/mindlock lock secret.pdf \
  --decoy \
  --max-fails 3 \
  --device-lock \
  --sensitivity confidential

# Wipe manually
./target/release/mindlock wipe secret.pdf.mindlock
```

### Phase 3 — Daemon + dashboard
```bash
# Start full stack
cp .env.example .env
docker-compose up -d

# Register a file with the daemon
curl -X POST http://localhost:8743/api/files \
  -H "Authorization: Bearer your-secret" \
  -H "Content-Type: application/json" \
  -d '{"file_id":"...","label":"Q3 Report","created_by":"you","policy_json":{},"trusted_devices":[]}'

# Lock with control server
./target/release/mindlock lock report.pdf \
  --server http://localhost:8743

# Remote revoke
curl -X POST http://localhost:8743/api/files/{id}/revoke \
  -H "Authorization: Bearer your-secret"

# View access log
curl http://localhost:8743/api/files/{id}/access-log \
  -H "Authorization: Bearer your-secret"

# Open dashboard
open dashboard/index.html
```

### Phase 3 — Behavior enrollment
```bash
# Enroll 5 keystroke samples
./target/release/mindlock enroll report.pdf.mindlock

# Future unlocks now require matching typing rhythm
```

### Phase 4 — Web3 / toklo.xyz
```bash
# Lock with ERC-20 token gate (requires 100 DWT tokens)
# Edit MindLockHeader.token_gate in your app:
# {
#   "chain_id": 137,
#   "token_contract": "0xYourDWTContractAddress",
#   "min_balance": 100000000000000000000,  // 100 tokens in wei
#   "rpc_url": "https://polygon-rpc.com"
# }
```

---

## Environment Variables

```bash
# mindlockd daemon
HOST=0.0.0.0
PORT=8743
DATABASE_URL=postgres://mindlock:mindlock@localhost/mindlock
API_SECRET=your-secret-key-here
RUST_LOG=mindlockd=info
RATE_LIMIT_RPM=60
```

---

## REST API Reference

| Method | Path | Description |
|--------|------|-------------|
| GET    | `/api/health` | Daemon health check |
| POST   | `/api/files` | Register a file |
| GET    | `/api/files/:id` | Get file metadata |
| POST   | `/api/files/:id/check-access` | Evaluate access (Grant/Deny/Decoy/Wipe) |
| POST   | `/api/files/:id/revoke` | Immediately revoke all access |
| POST   | `/api/files/:id/update-policy` | Update rules remotely |
| GET    | `/api/files/:id/access-log` | Access history (last 100) |
| POST   | `/api/files/:id/wipe` | Remote wipe signal |

### Access check request
```json
{
  "device_fingerprint": "abc123...",
  "ip_address": "1.2.3.4",
  "behavior_ok": true,
  "token_gate_ok": true
}
```

### Access check response
```json
{ "decision": "grant", "reason": null, "opens_remaining": 6 }
{ "decision": "decoy", "reason": null, "opens_remaining": null }
{ "decision": "deny",  "reason": "File has expired", "opens_remaining": null }
{ "decision": "wipe",  "reason": "Self-destruct triggered", "opens_remaining": 0 }
```

---

## Production Checklist

- [ ] Replace `API_SECRET` default with a 256-bit random secret
- [ ] Enable PostgreSQL SSL (`sslmode=require` in DATABASE_URL)
- [ ] Add HTTPS reverse proxy (nginx/Caddy) in front of mindlockd
- [ ] Implement full secp256k1 recovery in `wallet.rs` (add `k256` + `tiny-keccak` crates)
- [ ] Deploy MindLockLog.sol and set real contract address in `chain_log.rs`
- [ ] Integrate crossterm raw-mode key capture in `enroll.rs` for real keystroke timing
- [ ] Set up database backups for the access log

---

## Running Tests

```bash
# All tests
cargo test --workspace

# Core only (no network/DB required)
cargo test -p mindlock-core

# Specific test
cargo test -p mindlock-core crypto::tests::test_encrypt_decrypt_roundtrip -- --nocapture
```

---

## License

MIT
