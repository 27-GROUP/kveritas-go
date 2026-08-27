# K-Veritas Go

Standalone binary for tamper-evident verification of ML experiments. Cryptographically binds published results to the exact code, hardware, and time that produced them.

Works with any language -- Python, R, Julia, C++, shell scripts, etc. Zero runtime dependencies. Single static binary.

**Platform support.** Core features -- verify, seal, proofs, checkout, benchmark artifacts, the provenance timeline and disclosure levels -- are cross-platform (Linux, macOS, Windows). The fine-grained **activity map** (file reads/writes and subprocesses) and **per-process hardware attribution** are **Linux only** today; on other platforms they fall back gracefully (system-wide hardware, no activity map). macOS and Windows support for these is coming.

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

# 3. Seal the session: produces a signed PDF (redacted by default)
kveritas seal --output report.pdf
# Output: report.pdf  (+ report.pdf.kvbundle.zip when sealed at --disclosure open)

# 4. Verify the report (no server, no internet required)
kveritas verify report.pdf

# 5. Generate and check claims for paper submission
kveritas generate-claims --report report.pdf > claims.json
kveritas check --claims claims.json --report report.pdf

# 6. Self-update / cleanup
sudo kveritas update
kveritas clean
```

---

## Protocol Lines

The CLI recognizes these protocol line formats in stdout:

```
KVERITAS_METRIC name=<identifier> value=<float> [step=<label>]
KVERITAS_PHASE <phase_name>
KVERITAS_CLAIM <metric> <op> <value>
KVERITAS_INPUT src=seed:<value>
KVERITAS_MODEL params=<int> arch=<name> precision=<fp16|bf16|fp32>
KVERITAS_WORKLOAD dataset_size=<int> epochs=<float> batch_size=<int> [seq_len=<int>]
KVERITAS_ARTIFACT role=model|dataset [name=<ref>] path=<file> visibility=public|private
```

**KVERITAS_METRIC** -- Records a metric value at a specific line. The entire stdout is SHA-256 hashed byte-by-byte.

**KVERITAS_PHASE** -- Marks a phase boundary (e.g., "training", "evaluation"). At each boundary, a hardware snapshot is captured (CPU time, memory, GPU utilization, GPU memory, CPU temperature, disk I/O).

**KVERITAS_CLAIM** -- An inline assertion committed to the hash at a specific line number. Operators: `=`, `>=`, `<=`, `>`, `<`.

**KVERITAS_INPUT** -- Commits a PRNG seed to the record. Proves the seed was declared before results appeared.

**KVERITAS_MODEL** and **KVERITAS_WORKLOAD** -- Declare the model card (parameter count, architecture, precision) and the training workload (dataset size, epochs, batch size). These feed the compute-cost certificate, which checks that the declared work was physically performed on the reported hardware. Counts accept scientific notation (e.g. `params=25.6e6`).

**KVERITAS_ARTIFACT** -- Attest a model or dataset. A `public` artifact records its canonical content hash (matchable against a published reference, e.g. a standard benchmark); a `private` one records only a salted commitment that reveals nothing. See [Benchmark Artifacts](#benchmark-artifacts).

---

## Hardware Detection

At session start, K-Veritas captures a full hardware snapshot:

| Field | Source |
|---|---|
| CPU model | `/proc/cpuinfo` (Linux), `sysctl` (macOS) |
| CPU cores | `runtime.NumCPU()` |
| Memory (GB) | `/proc/meminfo` (Linux), `sysctl` (macOS) |
| GPU names | `nvidia-smi --query-gpu=name` (per GPU) |
| GPU count | Number of GPUs detected (multi-GPU / cluster support) |
| GPU memory | `nvidia-smi --query-gpu=memory.total` |
| OS / Arch | `runtime.GOOS` / `runtime.GOARCH` |

Multi-GPU setups report each GPU individually. The GPU count and names array are included in the signed data.

### Hardware Sampler (per-process)

During `kveritas run`, a background goroutine samples the cheap /proc counters (CPU time, memory, context switches, page faults, thread count, CPU frequency, per-process I/O) at about 10 Hz, and the slower per-process GPU counters (utilization, memory, power, temperature) at about 2 Hz, forward-filled in between. The high rate means even a short run accumulates enough samples for the coherence check; long runs are thinned to a fixed cap before sealing so the report stays small. These form a dense multi-channel time-series of actual compute activity, the basis for the HMCA coherence check and the verifier's telemetry graph.

Sampling is scoped to the run's **own process tree** -- CPU and memory from the tree, GPU memory and utilization filtered to its PIDs, GPU power scaled by its share of utilization. So another app on the machine (a browser, a second job) does **not** inflate the run's evidence.

> Per-process attribution is **Linux only** (it uses `/proc` and `nvidia-smi`). On macOS and Windows the sampler falls back to system-wide readings; per-OS support is coming.

---

## HMCA (Hardware-Metric Consistency Analyzer)

HMCA is metric-blind. It never compares the reported metric against hardware activity (that
comparison is confounded: the same result can legitimately cost very different amounts of work).
Instead it asks a question about the execution itself:

> Are the run's telemetry channels consistent shadows of one process?

A genuine computation drives every channel (CPU, memory, context switches, page faults, CPU
frequency, I/O, and, when a GPU is used, its utilization, memory, power, and temperature) from a
single underlying activity, so the channels co-fluctuate. A fabricated, replayed, or spliced trace
authors the channels independently, so the coupling breaks.

At `kveritas seal` time HMCA computes a **single-cause coherence score** (0.0-1.0) from the
per-process telemetry sampled during the run: it takes the active channels, removes their shared
trend (first difference), and measures how much of the variance is explained by one shared
component. High coherence means the channels move as one process. The verdict is `PASS` (coherent),
`WARN` (weak), `FAIL` (incoherent, possible fabrication or replay), or `N/A` (too little telemetry
to judge, e.g. a very short run; authenticity then rests on the signature, ledger, source
integrity, and provenance). A genuinely light run is judged on the consistency of the activity it
has, never penalized for being light. Score, verdict, and flags are baked into the canonical JSON
before signing and included in the report; the web verifier also renders the channels over time.

---

## Compute-Cost Attestation

When a run declares a model card via `KVERITAS_MODEL` and `KVERITAS_WORKLOAD`, `kveritas seal`
produces a per-run certificate that checks the declared computational work against the hardware
evidence sampled during the run. It proves the work was physically performed at the declared
scale; it does not prove the result is correct (that requires a rerun).

The certificate checks three physical bounds, all recomputable from values printed on the report:

| Bound | Impossible when |
|---|---|
| Time | declared FLOPs exceed the total the hardware could deliver (GPU peak times GPU-active seconds plus CPU peak times measured CPU core-seconds) |
| Energy | declared FLOPs exceed measured GPU joules divided by the minimum energy per FLOP |
| Memory | declared model weights exceed the observed GPU memory footprint (soft, review-only) |

The time bound sums the FLOP capacity of every device the run used, so it applies whether the work
ran on a GPU, only the CPU, or both. A 70B-parameter model declared on a machine with no GPU that
ran for a few seconds is caught as FABRICATION-IMPOSSIBLE, because no CPU could deliver that many
FLOPs in the measured core-seconds. Constants are chosen generous toward the author (theoretical
peak, an energy floor below any real device, all devices summed), so an honest run cannot trip the
accusatory verdict; a run with no declared card, or with no measurable compute at all, is marked
N/A. A hard violation is a physical impossibility and is non-deniable. The verdict
(PASS / REVIEW / FABRICATION-IMPOSSIBLE / N/A) is bound into the signed canonical JSON, so editing
the declared card to dodge the check breaks verification.

Example (Python):

```python
print("KVERITAS_MODEL params=25600000 arch=resnet50 precision=fp16")
print("KVERITAS_WORKLOAD dataset_size=1281167 epochs=90 batch_size=256")
```

---

## Provenance & Disclosure Levels

Every run is recorded as a signed timeline of content-addressed snapshots -- the state of the tracked source at run start, at each phase, and at run end, plus what changed between them. Each snapshot is a Merkle root linked to the previous one, so the timeline is tamper-evident and bound into the report signature.

You choose, per session, how much the report reveals. This controls disclosure only -- integrity is always committed.

| Level | Flag | Report shows |
|---|---|---|
| redacted (default) | `kveritas init` | Pseudonyms (`file#1`...), no names, no content |
| names | `kveritas init --show-names` | Real file names, no content bundled |
| open | `kveritas init --disclosure open` | Real names + a checkout bundle (code contents) |

A redacted report reveals **nothing sensitive**: no code, file names, datasets, weights, command line, or salt. The attestation server is zero-knowledge -- it only ever receives a hash. Leaf hashes are salted with a per-file key kept on your machine.

### Withholding files: `.kveritasignore`

Patterns in a `.kveritasignore` (gitignore-style) keep files out of any bundle -- e.g. a `secrets/` directory. A withheld file is still committed as a hash-only leaf (so it can never be silently dropped) and is listed as withheld, but its content is in no report and no bundle. Secrets like `.env` and key files are excluded by default.

---

## Selective-Disclosure Proofs

Reveal one file was part of a signed snapshot without exposing any other file:

```bash
kveritas prove report.pdf src/train.py          # -> kveritas-proof-train.py.json
kveritas verify-proof report.pdf kveritas-proof-train.py.json
```

The proof discloses only that file; the others appear as opaque commitments. It works across every run of a multi-run session. The `report.pdf.provkey.json` written at seal time is a **local** keystore (real paths + salts) that powers `prove` -- keep it private.

For agent sessions, the analogous proof reveals one recorded prompt or output and checks it against its committed hash, leaving every other entry a hash:

```bash
kveritas harness-prove session.json 1 --input prompt.txt -o proof.json
kveritas verify-harness-proof proof.json
```

Select the entry by index or `--tool-use-id`, and reveal the prompt side with `--input` or the response side with `--output-content`. Verification confirms the signed chain and that the revealed content re-hashes to the committed hash at that position.

---

## Checkout Bundle

Sealing at `--disclosure open` writes one bundle, `report.pdf.kvbundle.zip`, that reconstructs the code at any snapshot. A multi-run session merges every run into that single zip.

```bash
kveritas checkout report.pdf.kvbundle.zip run_end /tmp/out --report report.pdf
kveritas checkout report.pdf.kvbundle.zip run2:train /tmp/out --report report.pdf
```

The bundle holds source contents (content-addressed, deduplicated) plus a manifest per snapshot; never datasets, weights, or withheld files. Its hash is bound in the signed report, and each file is re-hashed against its manifest on checkout, so tampering is rejected. Always pass `--report` to verify against the signature.

---

## Benchmark Artifacts

Attest a benchmark score without exposing the model or the data. Declare each artifact and mark it public or private:

```python
print("KVERITAS_ARTIFACT role=model  path=weights/model.pt visibility=private")
print("KVERITAS_ARTIFACT role=dataset name=MMLU path=data/mmlu.bin visibility=public")
```

A `public` artifact records its canonical content hash, so a verifier can match it against an independently published reference (a standard benchmark, a released model) without you exposing it. A `private` artifact records only a salted commitment. The compute-cost certificate cross-checks that the evaluation actually consumed the compute a real forward pass requires.

It proves the evaluation ran as committed and produced that score. It does not prove a *private* eval set is fair, and it does not detect train/test contamination (future work).

---

## Cryptographic Protocol

```
canonical_json    = sorted_keys_compact_json(signing_data)
data_hash         = SHA-256(canonical_json)
nonce             = hex(16 random bytes)
signed_at         = RFC3339Nano UTC timestamp
payload           = "{data_hash}:{nonce}:{signed_at}"
signature         = RSA-PSS-SHA256(payload, salt=MAX, key=4096-bit)
signed_msg_hash   = SHA-256(payload)
visual_pdf_hash   = SHA-256(visual PDF pages before seal marker)
seal_block_hash   = SHA-256(entire seal JSON before seal_block_hash insertion)
```

All values plus the public key PEM and the canonical JSON bytes are embedded in the PDF after `%%EOF`, delimited by `%%KVERITAS_SEAL_BEGIN%%` and `%%KVERITAS_SEAL_END%%`.

The `canonical_json` field in the seal record stores the exact bytes that were hashed. Verifiers (including the Python API server) hash these bytes directly instead of reconstructing the signing data. This makes verification immune to future field additions -- no matter what new fields are added to the Go CLI's signing data, the Python verifier will always produce the correct hash.

`visual_pdf_hash` is computed over the visual PDF content (charts, tables, text) before the seal marker is appended. `seal_block_hash` is computed over the entire seal JSON before `seal_block_hash` itself is inserted, so any change to any seal field invalidates it. `source_bundle_hash` is included in the canonical JSON and binds the source bundle ZIP to the signed data.

Canonical JSON format: sorted keys at every level, compact separators (no spaces after `:` or `,`), UTF-8, ensure_ascii. Matches Python's `json.dumps(v, sort_keys=True, separators=(',', ':'))`.

---

## Commands

### `kveritas init`

```
--server URL                     Attestation server URL (default: hosted service)
--local                          Offline mode, skip server registration
--harness                        Record a hash-chained agent session (installs hooks)
--disclosure redacted|names|open How much the report reveals (default: redacted)
--show-names                     Keep real file names (same as --disclosure names)
```

Creates a `.kveritas/` session directory. Registers with the attestation server and binds a single-use token to the machine fingerprint.

Usage examples:
```bash
kveritas init                    # redacted (default), hosted attestation
kveritas init --local            # offline mode, sign with a local key
kveritas init --show-names       # real file names, no content bundled
kveritas init --disclosure open  # real names + a checkout bundle
```

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

Runs HMCA analysis, builds the provenance chain, computes the canonical hash, gets the server signature, and generates a multi-page PDF report with all data and crypto proof embedded. At `--disclosure open` it also writes `report.pdf.kvbundle.zip`. A local `report.pdf.provkey.json` keystore (for proofs) is written next to the report; keep it private.

### `kveritas verify <report.pdf | session.json>`

```
--public-key path   Override the embedded public key
```

Fully offline, no account. For an experiment PDF: data hash, RSA-PSS signature, visual PDF hash, provenance chain, and (if provided) the checkout bundle hash. For an agent session `.json`: server-signed genesis, full hash chain, and server-signed seal, localizing any inconsistency to the exact entry.

### `kveritas prove <report.pdf> <file>` / `kveritas verify-proof <report.pdf> <proof.json>`

Produce and check a selective-disclosure proof that one file was part of a signed snapshot, revealing nothing about the others. `prove` uses the local `.provkey.json` keystore.

### `kveritas checkout <bundle.zip> <[run:]snapshot> <outdir>`

```
--report path   Verify the bundle against the signed report first
```

Reconstruct a snapshot's files from an open-disclosure checkout bundle. The snapshot is a phase name, `run_start`/`run_end`, or an index, optionally prefixed with `run<N>:`.

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

Reports are fully compatible with the [K-Veritas Web Verifier](https://kveritas.org/verify). Reviewers can upload the report PDF, optionally the checkout bundle (`.kvbundle.zip`, open disclosure), and a manuscript PDF for a complete AI-powered audit:

1. Go to [kveritas.org/verify](https://kveritas.org/verify)
2. Upload the report PDF (and, for a code audit, the checkout bundle + manuscript)
3. Click Verify
4. See the Review Summary: crypto status, provenance timeline, attested artifacts, HMCA score, metrics, code audit verdict, claim mismatches

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
│   │   ├── sampler.go           Background hardware sampling goroutine
│   │   └── process_linux.go     Per-process CPU/mem/GPU attribution (Linux)
│   ├── provenance/             Merkle snapshots, disclosure, proofs, checkout bundle
│   ├── tracer/                 File + subprocess activity map (Linux)
│   ├── harness/                Hash-chained agent sessions
│   ├── compute/                Compute-cost certificate
│   ├── hmca/
│   │   ├── hmca.go              Hardware-Metric Consistency Analyzer
│   │   └── hmca_test.go         HMCA coherence tests
│   └── bundle/bundle.go         Source file collection + hashing
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
go test ./internal/hmca/ -v    # HMCA coherence tests

# Integration tests
kveritas-server --keys keys &
bash tests/run_tests.sh
```

---

## Related Repositories

| Repo | Purpose |
|---|---|
| [kveritas-go](https://github.com/27-GROUP/kveritas-go) | This repo -- the CLI and attestation server |
| [kveritas-releases](https://github.com/27-GROUP/kveritas-releases) | Pre-built binaries for all platforms |

---

## License

MIT License
