# Proving Benchmarks

Baseline numbers for the LP-0002 approve circuit, captured per PLAN.md
verification §5 ("one manual run of step 4 with `RISC0_DEV_MODE=0` to
confirm real proofs verify and record baseline proving time on the dev
machine"). These feed the eventual prize-submission benchmark table; the
nightly CI job (`.github/workflows/nightly-e2e.yml`) re-measures the same
path on hosted runners and uploads timing as an artifact.

## Real-proof baseline (RISC0_DEV_MODE=0)

| Metric | Value |
|---|---|
| Real SNARK proving — one approve proof | **161.1 s** (~2.7 min) |
| Real receipt verification — median of 5 | **45.8 ms** (min 38.6 ms, max 79.8 ms) |
| Guest cycles — total / user / paging | 262,144 / 214,325 / 25,530 |
| Reserved cycles | 22,289 |
| Segments | 1 |
| Receipt size — `borsh::to_vec` | 256,102 bytes |
| Journal (`ApprovePublicInputs`) | 96 bytes |

### Environment

- **Machine**: Apple M1, 8 cores, 8 GiB RAM (`macos-aarch64`)
- **OS**: macOS 26.4.1
- **risc0-zkvm**: `=3.0.5` (pinned), Risc0 rust toolchain `1.94.1`
- **Profile**: `--release`
- **Captured**: 2026-05-27

Proving comfortably sits inside the documented 1–10 min band, so the
30-minute sanity ceiling in `perf_baseline.rs` has wide headroom.

## Reproduce

```bash
# Real proofs (slow — multi-minute; the numbers are the artifact):
cargo test -p private_multisig_program --test perf_baseline --release \
  -- --ignored --nocapture

# Fast dev-mode profile (cycle counts, dev-mode timing, receipt size):
cargo test -p private_multisig_program --test perf_baseline -- --nocapture
```
