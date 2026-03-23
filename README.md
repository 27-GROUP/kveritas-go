# K-Veritas Go CLI

Standalone binary for tamper-evident verification of ML experiments. Cryptographically binds published results to the exact code, hardware, and time that produced them.

Works with any language: Python, R, Julia, C++, shell scripts. No runtime dependencies.

---

## Installation

```bash
make build
make server
```

Produces `bin/kveritas` and `bin/kveritas-server`.

**Cross-compile for all platforms:**
```bash
make cross
```
Outputs to `dist/` for linux/darwin/windows on amd64/arm64.

---

## Quick Start

```bash
# Start the attestation server (holds the private key)
kveritas-server --addr :7433 --keys keys

# In your project directory:
kveritas init --server http://localhost:7433
kveritas run -- python train.py --epochs 90
kveritas seal --output report.pdf

# Verify (no server needed)
kveritas verify report.pdf

# Cross-reference paper claims
kveritas generate-claims --report report.pdf > claims.json
kveritas check --claims claims.json --report report.pdf
```

**Offline mode (no server):**
```bash
kveritas init --local
kveritas run -- python train.py
kveritas seal --local-key keys/private.pem --output report.pdf
```

---

## Commands

### `kveritas init`

```
--server URL     Attestation server URL (default: http://localhost:7433)
--local          Offline mode, no server
```

Creates `.kveritas/` in the current directory. Registers with the server and stores a single-use token bound to the machine fingerprint.

### `kveritas run`

```
--files f1,f2   Source files to hash before and after the run
```

Runs the command as a monitored subprocess. Stdout/stderr are teed to the terminal while being hashed. Metrics printed as `KVERITAS_METRIC` lines are captured. Source files are hashed pre/post to detect modifications. Environment (`pip freeze`) is recorded.

### `kveritas seal`

```
--output, -o path   Output PDF path (default: kveritas-report-<id>.pdf)
--local-key path    Path to local RSA private key PEM
```

Computes a canonical SHA-256 hash of the complete session, sends only the hash to the server, receives a signature, and generates a PDF with all data and cryptographic proof embedded.

### `kveritas verify <report.pdf>`

```
--public-key path   Override the embedded public key
```

No account, no server, no internet required. Three sequential checks:
1. Re-hash embedded data, compare to stored data hash
2. Reconstruct payload, verify SHA-256 matches signed message hash
3. Verify RSA-PSS-SHA256 signature

Output: `VERIFIED`, `TAMPERED`, or `INVALID`.

### `kveritas check`

```
--claims claims.json   Claims file
--report report.pdf    Signed report
```

Verifies the report first, then cross-references each claimed metric value against the signed record.

### `kveritas generate-claims`

```
--report report.pdf   Path to a sealed K-Veritas report
```

Extracts all final metrics from a signed report and outputs a `claims.json` template to stdout. Authors edit this to match the values cited in their paper.

```json
{
  "claims": [
    { "metric": "val_accuracy", "value": 0.9471, "tolerance": 0.0001 },
    { "metric": "test_f1", "value": 0.9381, "tolerance": 0.0001 }
  ]
}
```

### `kveritas status`

Shows session ID, timestamps, machine, sealed state, and a summary of all runs.

---

## Metric Format

The only format guaranteed to be captured:

```
KVERITAS_METRIC name=<identifier> value=<float> [step=<label>]
```

Examples in any language:

```python
print(f"KVERITAS_METRIC name=val_accuracy value={acc:.6f} step={epoch}")
```
```r
cat(sprintf("KVERITAS_METRIC name=val_accuracy value=%.6f step=%d\n", acc, epoch))
```
```julia
println("KVERITAS_METRIC name=val_accuracy value=$(acc) step=$(epoch)")
```

The full stdout is SHA-256 hashed byte-for-byte. Each metric is anchored to its line number. Modifying any metric line invalidates the hash and the signature.

Heuristic patterns (Keras-style, JSON objects) are also detected as a convenience and marked `source: heuristic`.

---

## Attestation Server

```bash
kveritas-server --addr :7433 --keys /path/to/keys
```

Generates a 4096-bit RSA key pair on first start. Never commit `keys/private.pem`.

**Endpoints:**
| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/init` | POST | Register session, return single-use token |
| `/api/v1/seal` | POST | Validate token + machine ID, sign data hash |
| `/api/v1/public-key` | GET | Return public key PEM |

---

## Cryptographic Protocol

```
data_hash       = SHA-256(canonical_json(session_record))
nonce           = hex(16 random bytes)
signed_at       = RFC3339Nano UTC timestamp
payload         = "{data_hash}:{nonce}:{signed_at}"
signature       = RSA-PSS-SHA256(payload, salt=MAX, key=4096-bit)
signed_msg_hash = SHA-256(payload)
```

All values plus the public key PEM are embedded in the PDF after `%%EOF`. Standard PDF readers ignore this block.

Canonical JSON: sorted keys at every level, compact (no spaces), UTF-8. Matches Python's `json.dumps(v, sort_keys=True, separators=(',', ':'))`.

---

## Tests

```bash
kveritas-server --keys keys &
bash tests/run_tests.sh
```

14 integration tests covering init, run, seal, verify, tamper detection, claims checking, and status.

---

## Dependencies

- `github.com/spf13/cobra` -- CLI framework
- `github.com/google/uuid` -- session IDs

Everything else (crypto, PDF generation, HTTP) uses the Go standard library.

---

## License

MIT
