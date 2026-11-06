# mldsa-verify-otf

ML-DSA-65 signature verification (FIPS 204) with a small stack, for microcontrollers.

The matrix A and NTT(z) are never stored.
Each row of w is computed on its own and A is sampled on the fly, so the working set is two polynomials.
Verification only handles public data, so the code is not constant time.

## Usage

```rust
use mldsa_verify_otf::{verify, verify_with_context};

// pk: &[u8; PUBLIC_KEY_LEN], sig: &[u8; SIGNATURE_LEN]
verify(pk, message, sig)?;

// With a context string, and the message given in parts
verify_with_context(pk, b"context", &[header, body], sig)?;
```

## Stack usage

Measured on a Cortex-M3 in QEMU, in bytes:

| Verifier | Stack |
| --- | ---: |
| `mldsa-verify-otf` | ~3.6 k |
| `ml-dsa`, decode key and signature and verify | ~134 k |
| `ml-dsa`, verify with an already decoded key (43 k) | ~60 k |

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
