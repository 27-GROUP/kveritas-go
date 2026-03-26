# K-Veritas Go

Standalone binary for tamper-evident verification of ML experiments. Cryptographically binds published results to the exact code, hardware, and time that produced them.

Works with any language -- Python, R, Julia, C++, shell scripts. Zero runtime dependencies. Single static binary.

---

## Installation

### From source

Requires [Go 1.22+](https://go.dev/dl/).

```bash
git clone https://github.com/27-GROUP/kveritas-go.git
cd kveritas-go
make build
make server
```

Produces `bin/kveritas` and `bin/kveritas-server`.

### Pre-built binaries

Download from the [Releases](https://github.com/27-GROUP/kveritas-go/releases) page, or build cross-platform binaries locally:

```bash
make cross
```

This produces binaries in `dist/` for the following platforms:

| Platform | Architecture | Binary |
|---|---|---|
| Linux | x86_64 | `kveritas-linux-amd64` |
| Linux | ARM64 | `kveritas-linux-arm64` |
| macOS | Intel | `kveritas-darwin-amd64` |
| macOS | Apple Silicon | `kveritas-darwin-arm64` |
| Windows | x86_64 | `kveritas-windows-amd64.exe` |

The attestation server is also cross-compiled for Linux (amd64) and macOS (arm64).

### Install to PATH

After building, copy the binary to a directory on your PATH:

```bash
# Linux / macOS
sudo cp bin/kveritas /usr/local/bin/
sudo cp bin/kveritas-server /usr/local/bin/

# Or per-user
cp bin/kveritas ~/.local/bin/
```

On Windows, add the directory containing `kveritas.exe` to your `PATH` environment variable.

---

## Quick Start

No server setup required. The CLI connects to the hosted K-Veritas attestation service by default.

```bash
# 1. Initialize a session in your project directory
kveritas init

# 2. Run your experiments under kveritas
kveritas run -- python train.py --epochs 90
kveritas run -- python evaluate.py --checkpoint best

# 3. Seal the session into a signed PDF report
kveritas seal --output report.pdf

# 4. Verify the report (no server, no internet required)
kveritas verify report.pdf

# 5. Generate and check claims for paper submission
kveritas generate-claims --report report.pdf > claims.json
kveritas check --claims claims.json --report report.pdf
```

**Self-hosted server mode (optional):**

```bash
kveritas-server --addr :7433 --keys ./keys
kveritas init --server http://localhost:7433
```

**Offline mode (no server at all):**

```bash
kveritas init --local
kveritas run -- python train.py
kveritas seal --local-key keys/private.pem --output report.pdf
kveritas verify report.pdf
```

---

## Commands

### `kveritas init`

```
--server URL          Attestation server URL (default: https://kveritas-api-production.up.railway.app)
--local               Offline mode, skip server registration
--org-token TOKEN     Organization activation token (e.g. neurips_2026_a1b2c3d4)
```

Creates a `.kveritas/` session directory. By default, connects to the hosted K-Veritas attestation service. The session is registered and a single-use token bound to the machine fingerprint (SHA-256 of hostname, OS, architecture, CPU count) is stored. The server rejects seal requests from a different machine.

If `--org-token` is not provided, you will be prompted to enter an activation code (press Enter to skip). Organization tokens are issued by admins via the K-Veritas dashboard and link experiment runs to the issuing institution.

### `kveritas run`

```
--files f1,f2   Source files to hash before and after the run
```

Executes the given command as a monitored subprocess. Stdout and stderr are teed to the terminal in real time while being SHA-256 hashed. Every line is scanned for `KVERITAS_METRIC` entries. After the process exits, source files are re-hashed to detect modifications. The Python environment (`pip freeze`) is captured and hashed.

If `--files` is omitted, script files are detected heuristically from the command arguments (`.py`, `.R`, `.jl`, `.sh`, `.cpp`, etc.).

Each run produces `.kveritas/runs/<id>.json` containing the full record.

### `kveritas seal`

```
--output, -o path   Output PDF path (default: kveritas-report-<id>.pdf)
--local-key path    Path to a local RSA private key PEM for offline signing
```

Computes a canonical SHA-256 hash of the complete session (all run records, file hashes, stdout hashes, metrics, hardware, environment). Sends only this 64-character hash to the attestation server. Receives a signature, nonce, and timestamp. Generates a multi-page PDF report with all experiment data and cryptographic proof embedded.

### `kveritas verify <report.pdf>`

```
--public-key path   Override the embedded public key
```

Fully offline. No account, no server, no internet. The public key is embedded in the PDF at seal time. Performs three sequential checks:

1. Re-hash embedded session data and compare to the stored data hash
2. Reconstruct `payload = data_hash:nonce:signed_at` and verify its SHA-256 matches the stored signed message hash
3. Verify the RSA-PSS-SHA256 signature over the payload

Output: `VERIFIED`, `TAMPERED`, or `INVALID`.

### `kveritas check`

```
--claims claims.json   Path to claims file
--report report.pdf    Path to signed report
```

Runs `verify` first. If the report is tampered, aborts immediately. Otherwise, cross-references each claimed metric value against the signed record.

Per-claim output: `CONSISTENT`, `INCONSISTENT`, or `MISSING`.

### `kveritas generate-claims`

```
--report report.pdf   Path to a sealed K-Veritas report
```

Extracts all final metrics from a signed report and outputs a `claims.json` template to stdout. Authors edit this file to match the exact values cited in their paper and submit it alongside the PDF for reviewer verification.

Output:

```json
{
  "claims": [
    { "metric": "val_accuracy", "value": 0.9471, "tolerance": 0.0001 },
    { "metric": "test_f1", "value": 0.9381, "tolerance": 0.0001 }
  ]
}
```

### `kveritas status`

Displays session ID, timestamps, machine fingerprint, sealed state, and a summary of all recorded runs.

### `kveritas update`

Self-updates to the latest binary for the current OS and architecture. Downloads from the official release channel and replaces the running executable.

```bash
kveritas update          # may require sudo if installed system-wide
```

---

## Metric Format

The only format guaranteed to be captured and anchored in the signed hash:

```
KVERITAS_METRIC name=<identifier> value=<float> [step=<label>]
```

Add this line to your script's output in any language:

**Python:**
```python
print(f"KVERITAS_METRIC name=val_accuracy value={acc:.6f} step={epoch}")
```

**R:**
```r
cat(sprintf("KVERITAS_METRIC name=val_accuracy value=%.6f step=%d\n", acc, epoch))
```

**Julia:**
```julia
println("KVERITAS_METRIC name=val_accuracy value=$(acc) step=$(epoch)")
```

**C++:**
```cpp
printf("KVERITAS_METRIC name=val_accuracy value=%.6f step=%d\n", acc, epoch);
```

**Shell:**
```bash
echo "KVERITAS_METRIC name=val_accuracy value=0.9471 step=100"
```

Constraints:
- `name`: `[a-zA-Z][a-zA-Z0-9_]*`
- `value`: any float literal including scientific notation (`1.2e-4`)
- `step`: optional integer or string label (`final`, `epoch_10`)

The entire stdout stream is SHA-256 hashed byte-for-byte as the process runs. Each metric is anchored to its exact line number in the hash. Inserting, removing, or reordering metric lines invalidates the signature.

Heuristic patterns (Keras-style progress bars, JSON metric objects) are also detected as a convenience and marked `source: heuristic`. Do not rely on them for formal claims.

---

## Source Code Integrity

K-Veritas prevents code modification after experiments are run.

On the first `kveritas run`, all source files in the project directory are indexed and SHA-256 hashed. Supported extensions: `.py`, `.r`, `.R`, `.jl`, `.sh`, `.go`, `.cpp`, `.c`, `.h`, `.java`, `.rs`, `.js`, `.ts`, `.ipynb`, and more. Directories like `.git/`, `node_modules/`, `__pycache__/`, `venv/` are skipped.

During `kveritas seal`, the CLI:
1. Re-hashes all tracked source files and compares against stored hashes
2. **Refuses to seal** if any file was modified after the runs
3. Bundles all source files into `.kveritas/kveritas_bundle.zip`
4. Includes the SHA-256 of the zip in the signed data hash

This ensures the signed report is bound to the exact source code that produced the results.

```bash
kveritas init
kveritas run -- python train.py      # source files indexed on first run
# Editing train.py here will be detected
kveritas seal                        # REFUSED if train.py was modified
```

---

## Attestation Server

```bash
kveritas-server --addr :7433 --keys /path/to/keys
```

Generates a 4096-bit RSA key pair on first start. The private key never leaves the server.

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/init` | POST | Register session, return single-use token |
| `/api/v1/seal` | POST | Validate token + machine ID, sign data hash |
| `/api/v1/public-key` | GET | Return public key PEM |

The server validates:
- Token exists and matches the session
- Machine ID matches the one used at init
- Data hash is exactly 64 hex characters
- At least one run was recorded
- Session has not already been sealed

---

## Web Verification

Reports generated by this CLI are fully compatible with the [K-Veritas Web Verifier](https://kveritas-web.vercel.app/verify). Reviewers can verify reports in a browser with no installation:

1. Go to [kveritas-web.vercel.app/verify](https://kveritas-web.vercel.app/verify)
2. Drop the PDF
3. See instant verification result with all embedded metadata
4. Optionally drop `claims.json` to cross-reference paper claims

The web verifier calls the [K-Veritas API](https://kveritas-api-production.up.railway.app) which supports both Go-format and Python-format reports.

---

## Repository Structure

```
kveritas-go/
├── cmd/kveritas/main.go         CLI entry point (cobra commands)
├── cmd/kveritas/update.go       Self-update command
├── server/main.go               Attestation server (standalone binary)
├── internal/
│   ├── session/session.go       Data models, .kveritas/ I/O
│   ├── runner/runner.go         Subprocess wrapper, stdout tee, metric parsing
│   ├── metrics/parser.go        KVERITAS_METRIC parser + heuristic patterns
│   ├── crypto/crypto.go         RSA-PSS signing, SHA-256, canonical JSON
│   ├── pdf/generator.go         Self-contained PDF/1.4 writer
│   ├── client/client.go         HTTP client for attestation server
│   ├── hardware/hardware.go     Hardware snapshot + machine fingerprint
│   └── bundle/bundle.go         Source file collection, hashing, zip bundling
├── experiments/                  Mock experiment scripts
├── tests/
│   ├── run_tests.sh             Integration test suite (14 tests)
│   ├── mock_train.py            Mock training script
│   ├── mock_eval.py             Mock evaluation script
│   ├── mock_analysis.R          Mock R analysis script
│   ├── claims_correct.json      Valid claims fixture
│   └── claims_wrong.json        Invalid claims fixture
├── Makefile
├── go.mod
└── go.sum
```

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

All six values plus the public key PEM are embedded in the PDF after `%%EOF`, delimited by `%%KVERITAS_SEAL_BEGIN%%` and `%%KVERITAS_SEAL_END%%`. Standard PDF readers ignore this block.

Canonical JSON: sorted keys at every level, compact (no spaces after `:` or `,`), UTF-8. Matches Python's `json.dumps(v, sort_keys=True, separators=(',', ':'))` for cross-language compatibility.

---

## Dependencies

- [`github.com/spf13/cobra`](https://github.com/spf13/cobra) -- CLI framework
- [`github.com/google/uuid`](https://github.com/google/uuid) -- Session IDs

Everything else (RSA-PSS, SHA-256, PDF generation, HTTP server/client) uses the Go standard library.

---

## Tests

```bash
kveritas-server --keys keys &
bash tests/run_tests.sh
```

14 integration tests: init, double-init rejection, Python training run, metric capture, eval run, file tamper detection, seal, PDF metadata embedding, verify on clean report, tamper detection, correct claims, wrong claims, status, post-seal run rejection.

---

## License

MIT
