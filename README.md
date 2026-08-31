# K-Veritas Go

Cryptographic verification for computational experiments. Binds a result to the code, hardware, and time that produced it, in a signed PDF anyone can verify. Any language, no runtime deps, single static binary.

**Platform.** Core features are cross-platform. The activity map and per-process hardware are Linux only, with a system-wide fallback elsewhere.

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
| `KVERITAS_MODEL params=<int> arch=<name> precision=<fp16\|bf16\|fp32>` | Model card. |
| `KVERITAS_WORKLOAD dataset_size=<int> epochs=<float> batch_size=<int> [seq_len=<int>]` | Workload card. |
| `KVERITAS_ARTIFACT role=model\|dataset [name=<ref>] path=<file> visibility=public\|private` | Model or dataset. |

Auto-detected too: Keras history, sklearn CV, metric-like locals.

## Features

- **HMCA (execution coherence).** Metric-blind. Samples per-process telemetry at ~10 Hz, scores whether the channels move as one process. Verdict: PASS / WARN / FAIL / N/A.
- **Compute-cost.** From a model card, checks declared FLOPs against time, wall-clock, energy, and memory bounds. Verdict: PASS / REVIEW / FABRICATION-IMPOSSIBLE / N/A.
- **Provenance + disclosure.** Signed Merkle timeline of snapshots. Disclosure per session (redacted / names / open); integrity always committed. `.kveritasignore` withholds files as hash-only leaves.
- **Selective-disclosure proofs.** Prove one file, or one agent prompt/output, was in a signed snapshot without revealing the rest.
- **Checkout bundle.** `--disclosure open` writes a source bundle bound to the report; files re-hashed on checkout.
- **Benchmark artifacts.** Attest a score without exposing the model or data (public content hash, or private salted commitment).
- **Agent sessions.** `init --harness` records a hash-chained log of agent actions; verify localizes tampering to the exact entry.
- **Authenticity.** Signed by the K-Veritas key: `VERIFIED`. Any other key (e.g. `--local`): `SELF-ATTESTED`. The ledger is a hash chain.

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

## Cryptographic protocol

```
canonical_json = sorted-keys compact JSON of the signing data
data_hash      = SHA-256(canonical_json)
payload        = "{data_hash}:{nonce}:{signed_at}"
signature      = RSA-PSS-SHA256(payload, key=4096-bit)
```

The canonical JSON, signature, and public key are embedded after `%%EOF` between the seal markers. Verifiers hash the stored bytes directly.

## Web verification

Upload the report PDF at [kveritas.org/verify](https://kveritas.org/verify), optionally with the bundle and a manuscript. No account.

## Related repositories

- [kveritas-go](https://github.com/27-GROUP/kveritas-go): this repo, the CLI and server
- [kveritas-releases](https://github.com/27-GROUP/kveritas-releases): prebuilt binaries

## License

CLI, protocol, libraries: **Apache-2.0** ([LICENSE](LICENSE)). Server under `server/`: **AGPL-3.0** ([LICENSE-AGPL](LICENSE-AGPL)); a modified network service must publish its source or hold a commercial license.

"K-Veritas" is a trademark and cannot be used in any way that implies official certification.
