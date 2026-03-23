# K-Veritas Go — Technical Reference

> **Prototype.** This is a research prototype intended to demonstrate feasibility and attract collaborators. The cryptographic protocol is sound. The server is in-memory with no persistence across restarts. The PDF writer is a minimal self-contained implementation. Production hardening is explicitly out of scope at this stage.

---

## Repository layout

```
veritas_go/
├── cmd/kveritas/main.go          CLI entry point, all cobra commands
├── server/main.go                Attestation server (standalone binary)
├── internal/
│   ├── session/session.go        Data models, .kveritas/ I/O
│   ├── runner/runner.go          Subprocess wrapper, stdout tee, metric parsing
│   ├── metrics/parser.go         KVERITAS_METRIC parser + heuristic patterns
│   ├── crypto/crypto.go          RSA-PSS, SHA-256, canonical JSON hashing
│   ├── pdf/generator.go          Self-contained PDF writer, metadata embedding
│   ├── client/client.go          HTTP client for the attestation server
│   └── hardware/hardware.go      Hardware snapshot, machine fingerprint
├── experiments/                  Mock experiment scripts
├── tests/run_tests.sh            Integration test suite (14 tests)
└── reports/                      Signed PDF reports from mock experiments
```

External dependencies: `github.com/spf13/cobra`, `github.com/google/uuid`. Everything else — crypto, PDF generation, HTTP — uses the Go standard library.

---

## Data model

### Session

`.kveritas/session.json` — written by `init`, updated by each `run` and `seal`.

```go
type Session struct {
    ID         string    // UUID
    InitAt     time.Time
    ProjectDir string
    MachineID  string    // 8-byte hex fingerprint
    Token      string    // single-use server token
    ServerURL  string
    Runs       []string  // ordered run IDs
    Sealed     bool
}
```

### RunRecord

`.kveritas/runs/<id>.json` — one file per run.

```go
type RunRecord struct {
    ID          string
    SessionID   string
    Index       int
    Command     []string
    StartAt     time.Time
    EndAt       time.Time
    DurationSec float64
    ExitCode    int
    PreHashes   map[string]string  // path -> SHA-256
    PostHashes  map[string]string
    Modified    []string           // files that changed during run
    StdoutHash  string             // SHA-256 of full stdout
    StderrHash  string
    StdoutLines int
    Metrics     []Metric
    Hardware    HardwareInfo
    EnvDigest   string             // SHA-256 of pip freeze output
}
```

### Metric

```go
type Metric struct {
    Name   string
    Value  float64
    Step   string  // omitempty
    Line   int     // line number in stdout (1-indexed)
    Source string  // "explicit" or "heuristic"
}
```

`Line` is the anchor: it ties each metric to a specific position in the hashed stdout stream.

### SealRecord

`.kveritas/seal.json` — written by `seal`, also embedded in the PDF.

```go
type SealRecord struct {
    SessionID        string
    SealedAt         time.Time
    DataHash         string    // SHA-256 of canonical session JSON
    Nonce            string    // server-generated 32 hex chars
    SignedAt         string    // RFC3339Nano, server-generated
    Signature        string    // base64 RSA-PSS signature
    SignedMessageHash string   // SHA-256 of payload
    PublicKeyPEM     string    // embedded for offline verify
    ServerURL        string
}
```

---

## Cryptographic protocol

### Signing

```
canonical_json  = compact_sorted_key_json(signing_payload)
data_hash       = hex(SHA-256(canonical_json))
nonce           = hex(16 random bytes)                         [server]
signed_at       = RFC3339Nano UTC                              [server]
payload         = "{data_hash}:{nonce}:{signed_at}"
signature       = base64(RSA-PSS-SHA256(payload, salt=MAX))    [server]
signed_msg_hash = hex(SHA-256(payload))
```

**RSA parameters:** 4096-bit key, SHA-256 hash, MGF1-SHA256, salt length = maximum (`rsa.PSSSaltLengthAuto` in Go, `PSS.MAX_LENGTH` in Python cryptography). The two implementations interoperate: a Go-signed report verifies correctly under Python and vice versa.

**Signing payload (what gets hashed into `data_hash`):**

```json
{
  "session_id": "...",
  "init_at": "2026-03-21T00:25:59.123456789Z",
  "machine_id": "167ec0d6dc9a8170",
  "server_url": "http://...",
  "runs": [
    {
      "id": "...", "index": 0, "command": [...],
      "start_at": "...", "end_at": "...", "duration_sec": 0.67,
      "exit_code": 0,
      "pre_hashes": {"train.py": "abc123..."},
      "post_hashes": {"train.py": "abc123..."},
      "modified_files": [],
      "stdout_hash": "...", "stderr_hash": "...", "stdout_lines": 142,
      "metrics": [{"name": "val_accuracy", "value": 0.9471, "step": "10", "line": 47, "source": "explicit"}],
      "hardware": {"hostname": "...", "os": "linux", "arch": "amd64", "cpu_cores": 8, "mem_gb": 16.0},
      "env_digest": "..."
    }
  ]
}
```

The server never sees this JSON. It only receives `data_hash` (64 hex chars).

### Canonical JSON

Both Go and Python must produce identical bytes. The rules:
- Keys sorted lexicographically at every level
- Compact: no spaces after `:` or `,`
- UTF-8, ASCII-safe (non-ASCII escaped)
- Float64: shortest decimal representation that round-trips (Grisu/Ryu algorithm, identical between Go's `encoding/json` and Python's `json.dumps`)

Go: `sortedMarshal(v)` in `internal/crypto/crypto.go` — marshal → unmarshal to `interface{}` → recursive sorted re-serialization.

Python: `json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=True)`.

The `separators=(',', ':')` is critical. Python's default separators include spaces and produce a different hash.

### Verification (three sequential checks)

1. Recompute `data_hash` from embedded session+runs JSON. If mismatch → `TAMPERED`.
2. Reconstruct `payload = data_hash:nonce:signed_at`. Compute `SHA-256(payload)`. If mismatch with `signed_msg_hash` → `TAMPERED`.
3. Verify RSA-PSS signature over `payload` using the embedded public key. If invalid → `INVALID`.

---

## Runner: process wrapping and tee

`internal/runner/runner.go`

```
cmd.Start()
    ├── goroutine: stdoutPipe → bufio.Scanner
    │     ├── write line to os.Stdout          (user sees output)
    │     ├── write line to bytes.Buffer        (for stdout_hash)
    │     └── parser.Parse(line, lineNum)       (metric extraction)
    └── goroutine: stderrPipe → io.TeeReader(os.Stderr)
                                 └── bytes.Buffer (for stderr_hash)
cmd.Wait()
```

Both goroutines finish before `cmd.Wait()` returns, so all output is captured before hashing.

Pre-run and post-run file hashing happens synchronously on the main goroutine. If a file's SHA-256 changes between pre and post, its path appears in `RunRecord.Modified`.

---

## Metric parser

`internal/metrics/parser.go`

**Primary (explicit, guaranteed):**

```
KVERITAS_METRIC name=<id> value=<float> [step=<label>]
```

Regex: `^KVERITAS_METRIC\s+name=([a-zA-Z][a-zA-Z0-9_]*)\s+value=([+-]?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)(?:\s+step=(\S+))?`

A line without this prefix is never treated as an explicit metric, regardless of content.

**Heuristic patterns (best-effort, marked `source: heuristic`):**

| Pattern | Example |
|---------|---------|
| JSON metric object | `{"metric": "val_acc", "value": 0.94}` |
| Keras/Lightning multi-metric | `loss: 0.24 - val_accuracy: 0.94` |
| Single colon KV (metric keywords only) | `accuracy: 0.94` |

Heuristic metrics are captured for convenience but are excluded from the tamper-evidence guarantee in the sense that the `check` command will find them — but reviewers should only cite explicit metrics in formal claims.

**Why explicit metrics are non-cheat-able:**

The full stdout (including all `KVERITAS_METRIC` lines) is hashed. You cannot change a metric value in the stdout without changing `stdout_hash`, which is part of `data_hash`, which invalidates the signature. You cannot fabricate runs after the fact because the server issues tokens before the run and rejects out-of-sequence seals.

---

## Server

`server/main.go` — standard library `net/http`, no framework.

**Session lifecycle:**

```
POST /api/v1/init
  ← validates session_id, machine_id are present
  ← generates 32-char hex token (16 random bytes)
  ← stores {token, machine_id, init_at} in memory
  → returns {token}

POST /api/v1/seal
  ← validates token exists and matches session_id
  ← validates machine_id matches init machine_id
  ← validates data_hash is exactly 64 hex chars
  ← validates run_count >= 1
  ← marks session as sealed (prevents re-seal)
  ← generates nonce, signed_at, signs payload
  → returns {nonce, signed_at, signature, signed_message_hash, public_key_pem}

GET /api/v1/public-key
  → returns {public_key: "<PEM>"}
```

**Prototype limitations:**
- Sessions are in-memory. Server restart loses all session state. A client that `init`ed before a restart cannot `seal`.
- No rate limiting, no authentication on the public-key endpoint.
- Single server instance; no replication.

---

## PDF format

`internal/pdf/generator.go` — no external library. Self-contained PDF/1.4 writer.

**Visual content:** multi-page report with cover page (session summary, all metrics), per-run detail pages (command, timing, file hashes, stdout hash), and a cryptographic proof page (data hash, signed message hash, signature, verification instructions).

**Metadata embedding:** appended after `%%EOF`, invisible to PDF readers:

```
%%KVERITAS_SEAL_BEGIN%%
{
  "version": "1.0",
  "session": { ... },
  "runs": [ { ... }, ... ],
  "seal": { ... }
}
%%KVERITAS_SEAL_END%%
```

`kveritas verify` and the Python backend both search for these delimiters by byte scanning. No PDF parser needed for verification.

**Font:** Type1 built-in fonts only (Helvetica, Helvetica-Bold, Courier). No font embedding. WinAnsiEncoding. Non-ASCII characters are replaced with spaces by `pdfEscape`.

---

## Python backend compatibility

The existing FastAPI backend (`veritas-web/backend`) was updated to handle both PDF formats:

- **Format A (Python-generated):** metadata in PDF info dictionary fields (`/VeritasDataHash`, etc.) + named attachments (`experiment_data.json`, `signature.sig`). Verified against the server's own public key.
- **Format B (Go-generated):** `%%KVERITAS_SEAL_BEGIN%%` block. Verified against the public key embedded in the block itself — the backend does not need to hold the Go server's key.

The format is detected by scanning for `%%KVERITAS_SEAL_BEGIN%%` before attempting pypdf parsing.

The canonical hash in the Python validator uses `separators=(',', ':')` to produce compact JSON matching Go's output. This is the only non-obvious interoperability requirement.

---

## Machine ID

`hardware.MachineID()` returns `hex(SHA-256(hostname:goos:goarch:numcpu))[:16]`.

It is not a secret. Its purpose is replay-attack detection: a session token issued for machine A cannot be used to seal on machine B. It is not a strong identity guarantee — the server trusts whatever machine ID the client claims at `init` and checks consistency at `seal`.

---

## Known limitations (prototype)

- **Server state is in-memory.** Restart loses sessions. A client whose token is lost cannot seal — they must `init` again with a new session.
- **No rate limiting or abuse prevention** on the server.
- **Machine ID is self-reported.** A malicious client can claim any machine ID. The check is consistency between `init` and `seal`, not authenticity.
- **`pip freeze` as environment fingerprint.** Works for Python projects. For R or Julia experiments, `env_digest` will be empty (no pip available), which is recorded as an empty string and included in the signed data.
- **PDF writer is ASCII-only.** Non-ASCII characters in metric names, commands, or file paths are replaced with spaces in the visual output. The underlying JSON data is preserved correctly.
- **No hardware plausibility checks.** The server does not verify that the claimed training duration is consistent with the reported GPU. A researcher could run a fast job and claim it took longer.
- **Single binary, no hot reload.** The server must be restarted to rotate keys.
