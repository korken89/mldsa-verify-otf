//! Measures the peak stack usage of ML-DSA verification here, and of ML-DSA-65 verification in
//! the `ml-dsa` crate, on a Cortex-M3.
//!
//! Each measurement fills the free stack with a pattern, runs the verification and finds the
//! lowest word that changed. Run with `cargo run --release`, which starts QEMU.
#![no_std]
#![no_main]

use core::hint::black_box;

use cortex_m_rt::entry;
use ml_dsa::{Signature, VerifyingKey};
use mldsa_verify_otf::{MlDsa44, MlDsa65, MlDsa87, ParameterSet, verify};
use semihosting::{println, process};

/// A valid public key, message and signature for one parameter set.
struct Vector<P: ParameterSet> {
    pk: &'static P::PublicKey,
    msg: &'static [u8],
    sig: &'static P::Signature,
}

macro_rules! vector {
    ($set:literal) => {
        Vector {
            pk: include_bytes!(concat!(env!("OUT_DIR"), "/pk_", $set, ".bin")),
            msg: include_bytes!(concat!(env!("OUT_DIR"), "/msg_", $set, ".bin")),
            sig: include_bytes!(concat!(env!("OUT_DIR"), "/sig_", $set, ".bin")),
        }
    };
}

static V44: Vector<MlDsa44> = vector!("44");
static V65: Vector<MlDsa65> = vector!("65");
static V87: Vector<MlDsa87> = vector!("87");

const PAINT: u32 = 0xa5a5_a5a5;

unsafe extern "C" {
    /// Lowest address of the stack, from the `cortex-m-rt` linker script.
    static _stack_end: u32;
}

/// Runs `f` and returns its result with the bytes of stack it used. Captures and the return
/// value live in the caller's frame and are not counted.
#[inline(never)]
fn stack_usage<R>(f: impl FnOnce() -> R) -> (R, usize) {
    let bottom = (&raw const _stack_end).cast_mut();
    let sp = cortex_m::register::msp::read() as *mut u32;
    // SAFETY: Everything from the end of the stack up to the stack pointer is unused.
    let free = unsafe { sp.offset_from(bottom) } as usize;
    for i in 0..free {
        // SAFETY: In bounds of the unused stack, see above.
        unsafe { bottom.add(i).write_volatile(PAINT) };
    }
    let result = call(f);
    // SAFETY: In bounds of the unused stack, see above.
    let untouched = (0..free)
        .find(|&i| unsafe { bottom.add(i).read_volatile() } != PAINT)
        .unwrap_or(free);
    assert!(untouched > 0, "stack overflow");
    (result, (free - untouched) * 4)
}

/// Calls `f` in its own frame, so its locals are below the painted stack pointer.
#[inline(never)]
fn call<R>(f: impl FnOnce() -> R) -> R {
    black_box(f())
}

fn ours<P: ParameterSet>(v: &Vector<P>, sig: &P::Signature) -> bool {
    verify::<P>(black_box(v.pk), black_box(v.msg), black_box(sig)).is_ok()
}

fn ml_dsa_decode_key() -> VerifyingKey<ml_dsa::MlDsa65> {
    VerifyingKey::decode(black_box(V65.pk).into())
}

fn ml_dsa_decode_verify(sig: &<MlDsa65 as ParameterSet>::Signature) -> bool {
    ml_dsa_verify(&ml_dsa_decode_key(), sig)
}

fn ml_dsa_verify(
    key: &VerifyingKey<ml_dsa::MlDsa65>,
    sig: &<MlDsa65 as ParameterSet>::Signature,
) -> bool {
    Signature::<ml_dsa::MlDsa65>::decode(black_box(sig).into())
        .is_some_and(|sig| key.verify_with_context(black_box(V65.msg), &[], &sig))
}

/// Prints the stack usage of `verify` with a valid and an invalid signature.
fn row<P: ParameterSet>(name: &str, v: &Vector<P>, verify: impl Fn(&P::Signature) -> bool)
where
    P::Signature: Copy + AsMut<[u8]>,
{
    let mut bad_sig = *v.sig;
    bad_sig.as_mut()[0] ^= 1;
    let (valid, valid_bytes) = stack_usage(|| verify(v.sig));
    let (invalid, invalid_bytes) = stack_usage(|| verify(&bad_sig));
    assert!(valid && !invalid, "{name}");
    println!("  {name:<36} {valid_bytes:>7} {invalid_bytes:>7}");
}

#[entry]
fn main() -> ! {
    let (key, decode_bytes) = stack_usage(ml_dsa_decode_key);

    println!("ML-DSA verification stack usage in bytes:");
    println!("  {:<36} {:>7} {:>7}", "", "valid", "invalid");
    row("mldsa-verify-otf, ML-DSA-44", &V44, |sig| ours(&V44, sig));
    row("mldsa-verify-otf, ML-DSA-65", &V65, |sig| ours(&V65, sig));
    row("mldsa-verify-otf, ML-DSA-87", &V87, |sig| ours(&V87, sig));
    row(
        "ml-dsa decode and verify, ML-DSA-65",
        &V65,
        ml_dsa_decode_verify,
    );
    row("ml-dsa verify, decoded key, ML-DSA-65", &V65, |sig| {
        ml_dsa_verify(&key, sig)
    });
    println!();
    println!(
        "  {:<36} {decode_bytes:>7}",
        "ml-dsa key decode, without key"
    );
    println!(
        "  {:<36} {:>7}",
        "ml-dsa decoded key size",
        size_of::<VerifyingKey<ml_dsa::MlDsa65>>()
    );
    process::exit(0)
}
