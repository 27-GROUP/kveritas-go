# K-Veritas Go

Cryptographic verification for computational experiments. Binds a result to the code, hardware, and time that produced it, in a signed PDF anyone can verify. Any language, no runtime deps, single static binary.

**Platform.** Verify, seal, proofs, checkout, artifacts, provenance, disclosure: cross-platform. Activity map and per-process hardware: Linux only, system-wide fallback elsewhere.

## Install

```bash
# Prebuilt binary (also darwin/windows, amd64/arm64)
curl -fsSL https://github.com/27-GROUP/kveritas-releases/raw/main/bin/kveritas-linux-amd64 -o kveritas
chmod +x kveritas && sudo mv kveritas /usr/local/bin/

# Or build from source (Go 1.22+)
make build
```

## Quick start

```bash
kveritas init                                  # start a session (redacted by default)
kveritas run -- python train.py --epochs 90    # run under kveritas (any command)
kveritas run -- python evaluate.py
kveritas seal --output report.pdf              # signed PDF (+ bundle at --disclosure open)
kveritas verify report.pdf                     # verify (add --offline to skip the server)
```

## Protocol lines

Print to stdout in any language. Everything captured is signed.

| Line | Purpose |
|---|---|
| `KVERITAS_METRIC name=<id> value=<float> [step=<label>]` | A metric. |
| `KVERITAS_PHASE name=<phase>` | Phase boundary (hardware snapshot). |
| `KVERITAS_CLAIM metric=<id> value=<float>` | A headline claim. |
| `KVERITAS_INPUT src=seed:<value>` | A random seed. |
| `KVERITAS_MODEL params=<int> arch=<name> precision=<fp16\|bf16\|fp32>` | Model card (feeds compute-cost). |
| `KVERITAS_WORKLOAD dataset_size=<int> epochs=<float> batch_size=<int> [seq_len=<int>]` | Workload card. |
| `KVERITAS_ARTIFACT role=model\|dataset [name=<ref>] path=<file> visibility=public\|private` | Model or dataset. |

Auto-detected too: Keras history, sklearn CV, metric-like locals. Simple runs need no lines.

## HMCA (execution coherence)

Metric-blind. Never reads the result. Samples per-process telemetry at ~10 Hz: CPU, memory, context switches, page faults, CPU frequency, I/O, and GPU util/mem/power/temp. Scores whether the channels move as one process. Verdict: `PASS`, `WARN`, `FAIL`, or `N/A` (too little telemetry).

## Compute-cost attestation

Declare a model card. Seal checks declared FLOPs against what the hardware could deliver.

| Bound | Impossible when |
|---|---|
| Time | declared FLOPs exceed GPU peak x GPU-active seconds plus CPU peak x CPU core-seconds |
| Wall-clock | declared FLOPs need more seconds than the run lasted (catches a fast fake with no telemetry) |
| Energy | declared FLOPs exceed measured GPU joules over the minimum energy per FLOP |
| Memory | declared weights exceed observed GPU memory (soft) |

Bounds are generous; honest runs pass. Verdict: `PASS`, `REVIEW`, `FABRICATION-IMPOSSIBLE` (signed), or `N/A`.

## Provenance and disclosure

Each run: a signed timeline of content-addressed snapshots (run start, phases, run end, changes), Merkle-linked. Disclosure is per session; integrity is always committed.

| Level | Flag | Report shows |
|---|---|---|
| redacted (default) | `kveritas init` | Pseudonyms, no names, no content |
| names | `--show-names` | Real file names, no content |
| open | `--disclosure open` | Real names + a checkout bundle (code) |

Redacted reveals nothing sensitive; the server only sees a hash. `.kveritasignore` withholds files. A withheld file is still a hash-only leaf, listed, never silently dropped.

## Selective-disclosure proofs

Prove one file was in a signed snapshot, hide the rest:

```bash
kveritas prove report.pdf src/train.py
kveritas verify-proof kveritas-proof-train.py.json
```

Agent sessions: prove one prompt or output against its hash, others stay hashes:

```bash
kveritas harness-prove session.json 1 --input prompt.txt -o proof.json
kveritas verify-harness-proof proof.json
```

Select by index or `--tool-use-id`. Reveal the prompt with `--input`, the response with `--output-content`.

## Checkout bundle

`--disclosure open` writes `report.pdf.kvbundle.zip`: source contents (content-addressed, deduplicated) plus a per-snapshot manifest. No datasets or weights. Hash bound in the report; files re-hashed on checkout.

```bash
kveritas checkout report.pdf.kvbundle.zip run_end /tmp/out --report report.pdf
```

## Benchmark artifacts

Attest a score without exposing the model or data. `public`: content hash, matchable against a reference. `private`: salted commitment. Compute-cost checks the eval used real forward-pass compute.

## Agent sessions

`kveritas init --harness`: a hash-chained log of designated agent actions (installs Claude Code hooks). Each entry binds the agent, input/output as hashes, and order. Server signs genesis and seal. `verify session.json` recomputes the chain, localizes tampering to the exact entry, prints a per-agent tree.

## Verification and authenticity

`verify` checks the data hash, signature, visual PDF hash, and provenance locally, then the server audit (ledger, HMCA, code/paper with `--bundle`/`--paper`). Signed by the K-Veritas key: `VERIFIED`. Any other key (e.g. `--local`): `SELF-ATTESTED`, valid but of unconfirmed origin. The ledger is a hash chain; entries can't be altered, reordered, or removed undetected.

## Cryptographic protocol

```
canonical_json  = sorted-keys compact JSON of the signing data
data_hash       = SHA-256(canonical_json)
payload         = "{data_hash}:{nonce}:{signed_at}"
signature       = RSA-PSS-SHA256(payload, key=4096-bit)
visual_pdf_hash = SHA-256(visual PDF pages before the seal marker)
seal_block_hash = SHA-256(seal JSON before its own hash is inserted)
```

All values, the public key, and the canonical JSON are embedded after `%%EOF` between `%%KVERITAS_SEAL_BEGIN%%` and `%%KVERITAS_SEAL_END%%`. Verifiers hash the stored `canonical_json` directly, immune to future field additions.

## Commands

| Command | What it does |
|---|---|
| `init [--local] [--harness] [--disclosure redacted\|names\|open] [--show-names]` | Start a session. |
| `run -- <cmd>` | Run a command under kveritas. |
| `seal [-o path] [--local-key pem]` | Sign the session into a PDF. |
| `verify <report.pdf \| session.json \| proof.json> [--offline] [--bundle z] [--paper pdf]` | Local checks plus server audit. |
| `prove <report.pdf> <file...>` / `verify-proof <proof.json>` | File proof. |
| `harness-prove <session.json> <index\|--tool-use-id ID>` / `verify-harness-proof <proof.json>` | Prompt/output proof. |
| `checkout <bundle.zip> <[run:]snapshot> <dir> [--report r.pdf]` | Reconstruct a snapshot. |
| `check --claims c.json --report r.pdf` / `generate-claims --report r.pdf` | Check or derive paper claims. |
| `status` / `update` / `clean` | State, self-update, remove session. |

## Web verification

Upload the report PDF at [kveritas.org/verify](https://kveritas.org/verify) (optionally the bundle and a manuscript) for the seal, telemetry graph, provenance, metrics, code audit, and paper crosscheck. No account.

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

Dependencies: `spf13/cobra`, `google/uuid`. Else the Go standard library.

## Related repositories

| Repo | Purpose |
|---|---|
| [kveritas-go](https://github.com/27-GROUP/kveritas-go) | This repo: CLI and attestation server |
| [kveritas-releases](https://github.com/27-GROUP/kveritas-releases) | Prebuilt binaries for all platforms |

## License

CLI, protocol, libraries: **Apache-2.0** ([LICENSE](LICENSE)). Server under `server/`: **AGPL-3.0** ([LICENSE-AGPL](LICENSE-AGPL)); a modified network service must publish its source or hold a commercial license.

"K-Veritas" and its logo are trademarks. No rights to use the name or logo to imply official certification.
