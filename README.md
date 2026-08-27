# K-Veritas Go

Tamper-evident verification for computational experiments. It binds a published result to the exact code, hardware, and time that produced it, in a cryptographically signed PDF anyone can verify. Works with any language, zero runtime dependencies, single static binary.

**Platform.** Verify, seal, proofs, checkout, benchmark artifacts, provenance, and disclosure levels are cross-platform. The file/subprocess **activity map** and **per-process hardware attribution** are Linux-only today; elsewhere they fall back to system-wide readings.

## Install

Prebuilt binary:

```bash
curl -fsSL https://github.com/27-GROUP/kveritas-releases/raw/main/bin/kveritas-linux-amd64 -o kveritas
chmod +x kveritas && sudo mv kveritas /usr/local/bin/
```

Binaries: `kveritas-{linux,darwin,windows}-{amd64,arm64}`. Or build from source (Go 1.22+): `make build`.

## Quick start

```bash
kveritas init                                  # start a session (redacted by default)
kveritas run -- python train.py --epochs 90    # run under kveritas (any command)
kveritas run -- python evaluate.py
kveritas seal --output report.pdf              # signed PDF (+ bundle at --disclosure open)
kveritas verify report.pdf                     # verify (add --offline to skip the server)
```

## Protocol lines

Print these to stdout in any language; everything captured is bound into the signed record.

| Line | Purpose |
|---|---|
| `KVERITAS_METRIC name=<id> value=<float> [step=<label>]` | Record a metric. |
| `KVERITAS_PHASE name=<phase>` | Mark a phase boundary (hardware snapshot). |
| `KVERITAS_CLAIM metric=<id> value=<float>` | Commit a headline claim. |
| `KVERITAS_INPUT src=seed:<value>` | Commit a random seed. |
| `KVERITAS_MODEL params=<int> arch=<name> precision=<fp16\|bf16\|fp32>` | Model card (feeds compute-cost). |
| `KVERITAS_WORKLOAD dataset_size=<int> epochs=<float> batch_size=<int> [seq_len=<int>]` | Workload card. |
| `KVERITAS_ARTIFACT role=model\|dataset [name=<ref>] path=<file> visibility=public\|private` | Attest a model or dataset. |

Common metrics are also auto-detected (Keras history, sklearn CV, metric-like locals), so simple runs need no lines.

## HMCA (execution coherence)

Metric-blind. It never looks at the reported result. During the run a background sampler records per-process telemetry (CPU, memory, context switches, page faults, CPU frequency, I/O, and, when a GPU is used, its utilization, memory, power, temperature) at about 10 Hz. At seal time HMCA scores whether those channels co-fluctuate as shadows of one process: a genuine run drives them all from one activity, a fabricated or replayed trace does not. Verdict is `PASS` (coherent), `WARN`, `FAIL` (incoherent), or `N/A` (too little telemetry to judge). A light run is judged on the activity it has, never penalized for being light. The web verifier renders the channels over time.

## Compute-cost attestation

When a run declares a model card, seal produces a certificate checking the declared FLOPs against what the hardware could physically deliver.

| Bound | Impossible when |
|---|---|
| Time | declared FLOPs exceed GPU peak x GPU-active seconds plus CPU peak x CPU core-seconds |
| Energy | declared FLOPs exceed measured GPU joules divided by the minimum energy per FLOP |
| Memory | declared weights exceed observed GPU memory (soft) |

The time bound sums every device, so it fires whether the work ran on GPU, CPU, or both (a 175B model declared on an idle CPU is caught). Bounds are generous, so honest runs pass; no card or no telemetry is `N/A`. A hard violation is `FABRICATION-IMPOSSIBLE`, bound into the signature.

## Provenance and disclosure

Each run is a signed timeline of content-addressed snapshots (source state at run start, each phase, and run end, plus what changed), Merkle-linked and bound into the signature. You choose per session how much is revealed; this controls disclosure only, integrity is always committed.

| Level | Flag | Report shows |
|---|---|---|
| redacted (default) | `kveritas init` | Pseudonyms, no names, no content |
| names | `--show-names` | Real file names, no content |
| open | `--disclosure open` | Real names + a checkout bundle (code) |

A redacted report reveals nothing sensitive (no code, names, data, weights, command line, or salt); the server only ever receives a hash. Patterns in `.kveritasignore` keep files out of any bundle; a withheld file is still committed as a hash-only leaf and listed as withheld, so it cannot be silently dropped.

## Selective-disclosure proofs

Reveal one file was in a signed snapshot without exposing the others:

```bash
kveritas prove report.pdf src/train.py
kveritas verify-proof kveritas-proof-train.py.json
```

For agent sessions, prove one recorded prompt or output against its committed hash, leaving every other entry a hash:

```bash
kveritas harness-prove session.json 1 --input prompt.txt -o proof.json
kveritas verify-harness-proof proof.json
```

Select the entry by index or `--tool-use-id`; reveal the prompt with `--input` or the response with `--output-content`.

## Checkout bundle

Sealing at `--disclosure open` writes `report.pdf.kvbundle.zip`, holding source contents (content-addressed, deduplicated) plus a manifest per snapshot, never datasets or weights. Its hash is bound in the report; each file is re-hashed on checkout.

```bash
kveritas checkout report.pdf.kvbundle.zip run_end /tmp/out --report report.pdf
```

## Benchmark artifacts

Attest a benchmark score without exposing the model or data. A `public` artifact records its content hash (matchable against a published reference); a `private` one records only a salted commitment. Compute-cost cross-checks that the evaluation consumed the compute a real forward pass requires.

## Agent sessions

`kveritas init --harness` records a hash-chained log of designated agent actions (installs Claude Code hooks). Each entry binds the acting agent, the input/output content as hashes, and its position, giving existence, content, and order; the server signs the genesis and the seal. `kveritas verify session.json` recomputes the chain and localizes any tampering to the exact entry, with a per-agent attribution tree.

## Cryptographic protocol

```
canonical_json  = sorted-keys compact JSON of the signing data
data_hash       = SHA-256(canonical_json)
payload         = "{data_hash}:{nonce}:{signed_at}"
signature       = RSA-PSS-SHA256(payload, key=4096-bit)
visual_pdf_hash = SHA-256(visual PDF pages before the seal marker)
seal_block_hash = SHA-256(seal JSON before its own hash is inserted)
```

All values, the public key, and the canonical JSON bytes are embedded after `%%EOF` between `%%KVERITAS_SEAL_BEGIN%%` and `%%KVERITAS_SEAL_END%%`. Verifiers hash the stored `canonical_json` directly, so verification is immune to future field additions.

## Commands

| Command | What it does |
|---|---|
| `init [--local] [--harness] [--disclosure redacted\|names\|open] [--show-names]` | Start a session. |
| `run -- <cmd>` | Run a command under kveritas, capturing telemetry and protocol lines. |
| `seal [-o path] [--local-key pem]` | Sign the session into a PDF (+ bundle at open disclosure). |
| `verify <report.pdf \| session.json \| proof.json> [--offline] [--bundle z] [--paper pdf]` | Local checks plus the full server audit. |
| `prove <report.pdf> <file...>` / `verify-proof <proof.json>` | Selective-disclosure proof for files. |
| `harness-prove <session.json> <index\|--tool-use-id ID>` / `verify-harness-proof <proof.json>` | Proof for a recorded prompt/output. |
| `checkout <bundle.zip> <[run:]snapshot> <dir> [--report r.pdf]` | Reconstruct a snapshot's files. |
| `check --claims c.json --report r.pdf` / `generate-claims --report r.pdf` | Check or derive paper claims. |
| `status` / `update` / `clean` | Session state, self-update, remove the session directory. |

## Web verification

Upload the report PDF at [kveritas.org/verify](https://kveritas.org/verify) (optionally the checkout bundle and a manuscript PDF) for the cryptographic seal, execution-coherence telemetry graph, provenance, metrics, AI code audit, and paper crosscheck. No account required.

## Repository structure

```
cmd/kveritas/       CLI entry point
server/             Attestation server
internal/
  session/          Data models, .kveritas/ I/O
  runner/           Subprocess wrapper, telemetry sampler
  crypto/           RSA-PSS, SHA-256, canonical JSON
  pdf/              Self-contained PDF writer
  client/           Attestation server client
  hardware/         Hardware snapshot + per-process sampling (Linux)
  provenance/       Merkle snapshots, disclosure, proofs, checkout
  tracer/           File/subprocess activity map (Linux)
  harness/          Hash-chained agent sessions + proofs
  compute/          Compute-cost certificate
  hmca/             Execution-coherence analyzer
  bundle/           Source collection + hashing
```

Dependencies: `spf13/cobra` (CLI) and `google/uuid` (IDs); everything else is the Go standard library.

## Related repositories

| Repo | Purpose |
|---|---|
| [kveritas-go](https://github.com/27-GROUP/kveritas-go) | This repo: the CLI and attestation server |
| [kveritas-releases](https://github.com/27-GROUP/kveritas-releases) | Prebuilt binaries for all platforms |

## License

The CLI, protocol, and verification libraries are licensed under **Apache-2.0** ([LICENSE](LICENSE)).

The attestation server under `server/` is licensed under **AGPL-3.0** ([LICENSE-AGPL](LICENSE-AGPL)). Running a modified version as a network service requires publishing your source under the same license, or obtaining a commercial license.

"K-Veritas" and its logo are trademarks. The license grants no rights to use the name or logo to run a service that implies official K-Veritas certification.
