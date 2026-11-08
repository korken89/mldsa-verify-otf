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

## Stack usage

Measured on a Cortex-M3 in QEMU, in bytes:

| Verifier | Stack |
| --- | ---: |
| `mldsa-verify-otf`, any parameter set | ~3.6 k |
| `ml-dsa`, ML-DSA-65, decode key and signature and verify | ~134 k |
| `ml-dsa`, ML-DSA-65, verify with an already decoded key (43 k) | ~60 k |

The exact numbers are in [`qemu/stack-usage.txt`](qemu/stack-usage.txt) and CI fails if they change.

## Testing

The flake has the toolchain and QEMU:

```console
$ nix develop
$ make test   # host tests and the QEMU stack usage check
$ make lint   # rustfmt and clippy
$ make bless  # update qemu/stack-usage.txt after an intended change
```

The host tests run the Wycheproof and NIST ACVP vectors, and cross check against the `ml-dsa` crate.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at your option.
