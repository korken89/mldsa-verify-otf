# mldsa-verify-otf

ML-DSA signature verification (FIPS 204) with a small stack, for microcontrollers.
All three parameter sets are supported: ML-DSA-44, ML-DSA-65 and ML-DSA-87.

The matrix A and NTT(z) are never stored.
Each row of w is computed on its own and A is sampled on the fly, so the working set is two polynomials.
Verification only handles public data, so the code is not constant time.

## ⚠️ Security Warning

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!

There is no protection against fault injection, such as voltage glitches.

## Usage

```rust
use mldsa_verify_otf::{MlDsa65, verify, verify_with_context};

// pk: &[u8; 1952], sig: &[u8; 3309]
verify::<MlDsa65>(pk, message, sig)?;

// With a context string, and the message given in parts
verify_with_context::<MlDsa65>(pk, b"context", &[header, body], sig)?;
```

## Measurements

On a Cortex-M3 (mps2-an385) and a Cortex-M33 (mps2-an505) in QEMU, with opt-level "s", fat LTO and one codegen unit, for a valid signature.
Overflow checks are off, as in the release profile of the `qemu` crate, and the numbers depend on the profile of the consumer.
With overflow checks on, the M33 executes about 10% more instructions.
The stack is the peak use of a painted stack in bytes, and the instructions are exact counts from a QEMU plugin (`qemu/icount.c`).

| Verifier | M3 stack | M33 stack | M3 instructions | M33 instructions |
| --- | ---: | ---: | ---: | ---: |
| `mldsa-verify-otf`, ML-DSA-44 | 3,472 | 3,464 | 5,831,613 | 5,771,164 |
| `mldsa-verify-otf`, ML-DSA-65 | 3,464 | 3,472 | 10,284,398 | 10,173,537 |
| `mldsa-verify-otf`, ML-DSA-87 | 3,464 | 3,472 | 18,199,635 | 17,993,159 |
| `ml-dsa` 0.1.1, ML-DSA-65, decode key and signature and verify | 134,484 | 134,484 | 10,992,314 | 10,880,402 |
| `ml-dsa` 0.1.1, ML-DSA-65, verify with an already decoded key (43 k) | 60,116 | 60,124 | 2,258,276 | 2,281,015 |

QEMU does not model cycles, so the instruction counts are a proxy for time.
All numbers, also for an invalid signature, are in [`qemu/stack-usage.txt`](qemu/stack-usage.txt) and CI fails if they change.

## Testing

The flake has the toolchain, QEMU and the tools for the plugin:

```console
$ nix develop
$ make test   # host tests and the QEMU measurements
$ make lint   # rustfmt and clippy
$ make bless  # update qemu/stack-usage.txt after an intended change
```

The host tests run the Wycheproof and NIST ACVP vectors, and cross check against the `ml-dsa` crate.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
