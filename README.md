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

Download from the [releases repo](https://github.com/27-GROUP/kveritas-releases):

```bash
curl -fsSL https://github.com/27-GROUP/kveritas-releases/raw/main/bin/kveritas-linux-amd64 -o kveritas
chmod +x kveritas
sudo mv kveritas /usr/local/bin/
```

Available platforms:

| Platform | Architecture | Binary |
|---|---|---|
| Linux | x86_64 | `kveritas-linux-amd64` |
| Linux | ARM64 | `kveritas-linux-arm64` |
| macOS | Intel | `kveritas-darwin-amd64` |
| macOS | Apple Silicon | `kveritas-darwin-arm64` |
| Windows | x86_64 | `kveritas-windows-amd64.exe` |

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

---

## Protocol Lines

The CLI recognizes four protocol line formats in stdout:

```
KVERITAS_METRIC name=<identifier> value=<float> [step=<label>]
KVERITAS_PHASE <phase_name>
KVERITAS_CLAIM <metric> <op> <value>
KVERITAS_INPUT src=seed:<value>
```

**KVERITAS_METRIC** -- Records a metric value at a specific line. The entire stdout is SHA-256 hashed byte-by-byte.

**KVERITAS_PHASE** -- Marks a phase boundary (e.g., "training", "evaluation"). At each boundary, a hardware snapshot is captured (CPU time, memory, GPU utilization, GPU memory, CPU temperature, disk I/O).

**KVERITAS_CLAIM** -- An inline assertion committed to the hash at a specific line number. Operators: `=`, `>=`, `<=`, `>`, `<`.

**KVERITAS_INPUT** -- Commits a PRNG seed to the record. Proves the seed was declared before results appeared.

---

## Hardware Sampler

During `kveritas run`, a background goroutine polls hardware counters every 15 seconds: CPU time, memory usage, GPU utilization, GPU memory, CPU temperature, and disk I/O. These samples are included in the signed data, providing a time-series trace of actual compute activity.

---

## HMCA (Hardware-Metric Consistency Analyzer)

At `kveritas seal` time, a deterministic rule engine analyzes the relationship between hardware telemetry and reported metrics:

| Rule | Condition | Meaning |
|---|---|---|
| `ZERO_COST_METRIC` | Metric reported but total CPU time < 1s | Metric produced without measurable computation |
| `LOW_ACTIVITY_HIGH_GAIN` | High metric value but peak CPU < 5% | Complex results with minimal resource usage |
| `GPU_CLAIM_NO_GPU` | GPU counters reported but no GPU detected | Claims GPU training on CPU-only machine |
| `IDLE_RUN` | Hardware completely idle for entire run (>60s) | No computation occurred |
| `PHASE_MISMATCH` | Eval phase used more CPU than training phase | Suspicious resource distribution |

The HMCA produces a score (0.0-1.0), verdict (PASS/WARN/FAIL), and triggered flags. These are baked into the canonical JSON before signing and included in the PDF report.

---

## Source Code Integrity

K-Veritas prevents code modification after experiments are run.

On the first `kveritas run`, all source files are indexed and SHA-256 hashed. During `kveritas seal`:

1. Re-hashes all tracked source files and compares against stored hashes
2. Refuses to seal if any file was modified after the runs
3. Computes an aggregate source code hash (SHA-256 over sorted file hashes)
4. Bundles all source files into `bundle.zip`
5. Includes both the source code hash and bundle hash in the signed data

---

## Cryptographic Protocol

```
canonical_json  = sorted_keys_compact_json(signing_data)
data_hash       = SHA-256(canonical_json)
nonce           = hex(16 random bytes)
signed_at       = RFC3339Nano UTC timestamp
payload         = "{data_hash}:{nonce}:{signed_at}"
signature       = RSA-PSS-SHA256(payload, salt=MAX, key=4096-bit)
signed_msg_hash = SHA-256(payload)
```

All values plus the public key PEM and the canonical JSON bytes are embedded in the PDF after `%%EOF`, delimited by `%%KVERITAS_SEAL_BEGIN%%` and `%%KVERITAS_SEAL_END%%`.

The `canonical_json` field in the seal record stores the exact bytes that were hashed. Verifiers (including the Python API server) hash these bytes directly instead of reconstructing the signing data. This makes verification immune to future field additions -- no matter what new fields are added to the Go CLI's signing data, the Python verifier will always produce the correct hash.

Canonical JSON format: sorted keys at every level, compact separators (no spaces after `:` or `,`), UTF-8, ensure_ascii. Matches Python's `json.dumps(v, sort_keys=True, separators=(',', ':'))`.

---

## Commands

### `kveritas init`

```
--server URL          Attestation server URL (default: hosted service)
--local               Offline mode, skip server registration
--org-token TOKEN     Organization activation token
```

Creates a `.kveritas/` session directory. Registers with the attestation server and binds a single-use token to the machine fingerprint.

### `kveritas run`

```
--files f1,f2   Source files to hash before and after the run
```

Executes the command as a monitored subprocess. Stdout/stderr are teed to the terminal while being SHA-256 hashed. Protocol lines are parsed in real time. A background hardware sampler polls every 15 seconds. Source files are re-hashed after exit.

### `kveritas seal`

```
--output, -o path   Output PDF path (default: kveritas-report-<id>.pdf)
--local-key path    Path to a local RSA private key PEM for offline signing
```

Runs HMCA analysis, computes aggregate source hash, creates bundle.zip, computes canonical hash, gets server signature, and generates a multi-page PDF report with all data and crypto proof embedded.

### `kveritas verify <report.pdf>`

```
--public-key path   Override the embedded public key
```

Fully offline. Three-step verification: data hash match, signed message hash match, RSA-PSS signature verification.

### `kveritas check`

```
--claims claims.json   Path to claims file
--report report.pdf    Path to signed report
```

Verifies the report first, then cross-references each claimed metric value against the signed record.

### `kveritas generate-claims`

```
--report report.pdf   Path to a sealed K-Veritas report
```

Extracts all final metrics and outputs a `claims.json` template.

### `kveritas update`

Self-updates to the latest binary for the current OS and architecture.

### `kveritas status`

Displays session info, timestamps, machine fingerprint, and run summaries.

### `kveritas clean`

Manually removes the `.kveritas/` directory to abandon a session.

---

## Web Verification

Reports are fully compatible with the [K-Veritas Web Verifier](https://kveritas.org/verify). Reviewers can upload the report PDF, source bundle ZIP, and manuscript PDF for a complete AI-powered audit:

1. Go to [kveritas.org/verify](https://kveritas.org/verify)
2. Upload report PDF, bundle ZIP, and manuscript PDF
3. Click Verify
4. See the Review Summary: crypto status, HMCA score, recorded metrics, code audit verdict, claim mismatches

---

## Repository Structure

```
kveritas-go/
├── cmd/kveritas/main.go         CLI entry point (cobra commands)
├── cmd/kveritas/update.go       Self-update command
├── server/main.go               Attestation server (standalone binary)
├── internal/
│   ├── session/session.go       Data models, .kveritas/ I/O
│   ├── runner/runner.go         Subprocess wrapper, stdout tee, hardware sampler
│   ├── metrics/parser.go        KVERITAS_METRIC parser + heuristic patterns
│   ├── crypto/crypto.go         RSA-PSS signing, SHA-256, canonical JSON
│   ├── pdf/generator.go         Self-contained PDF/1.4 writer (includes HMCA page)
│   ├── client/client.go         HTTP client for attestation server
│   ├── hardware/
│   │   ├── hardware.go          Hardware snapshot + machine fingerprint
│   │   └── sampler.go           Background hardware sampling goroutine
│   ├── hmca/
│   │   ├── hmca.go              Hardware-Metric Consistency Analyzer (5 rules)
│   │   └── hmca_test.go         HMCA unit tests (8 tests)
│   └── bundle/bundle.go         Source file collection, hashing, zip bundling
├── tests/
│   ├── run_tests.sh             Integration test suite
│   └── *.py, *.json             Mock experiments and claim fixtures
├── Makefile
├── go.mod
└── go.sum
```

---

## Dependencies

- [`github.com/spf13/cobra`](https://github.com/spf13/cobra) -- CLI framework
- [`github.com/google/uuid`](https://github.com/google/uuid) -- Session IDs

Everything else (RSA-PSS, SHA-256, PDF generation, HTTP server/client, hardware sampling) uses the Go standard library.

---

## Tests

```bash
# Unit tests
go test ./internal/hmca/ -v    # 8 HMCA rule tests

# Integration tests
kveritas-server --keys keys &
bash tests/run_tests.sh
```

---

## Related Repositories

| Repo | Purpose | Live URL |
|---|---|---|
| [kveritas-api](https://github.com/27-GROUP/kveritas-api) | FastAPI backend (signing, verification, AI audit) | [kveritas-api-production.up.railway.app](https://kveritas-api-production.up.railway.app) |
| [kveritas-web](https://github.com/27-GROUP/kveritas-web) | Next.js frontend (web verifier, admin dashboard) | [kveritas.org](https://kveritas.org) |
| [kveritas-releases](https://github.com/27-GROUP/kveritas-releases) | Pre-built binaries for all platforms | |

The frontend and API also have private mirrors (`Mamadou2727/kveritas-web`, `Mamadou2727/kveritas-api`) connected to Vercel and Railway for auto-deploy. The Go CLI repo stays on 27-GROUP only.

---

## License

MIT License
