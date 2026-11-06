//! Measures the peak stack usage of ML-DSA-65 verification, here and in the `ml-dsa` crate, on a
//! Cortex-M3.
//!
//! Each measurement fills the free stack with a pattern, runs the verification and finds the
//! lowest word that changed. Run with `cargo run --release`, which starts QEMU.
#![no_std]
#![no_main]

use core::hint::black_box;

use cortex_m_rt::entry;
use ml_dsa::{MlDsa65, Signature, VerifyingKey};
use mldsa_verify_otf::{PUBLIC_KEY_LEN, SIGNATURE_LEN, verify};
use semihosting::{println, process};

static PK: &[u8; PUBLIC_KEY_LEN] = include_bytes!(concat!(env!("OUT_DIR"), "/pk.bin"));
static SIG: &[u8; SIGNATURE_LEN] = include_bytes!(concat!(env!("OUT_DIR"), "/sig.bin"));
static MSG: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/msg.bin"));

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

fn ours(sig: &[u8; SIGNATURE_LEN]) -> bool {
    verify(black_box(PK), black_box(MSG), black_box(sig)).is_ok()
}

fn ml_dsa_decode_key() -> VerifyingKey<MlDsa65> {
    VerifyingKey::decode(black_box(PK).into())
}

fn ml_dsa_decode_verify(sig: &[u8; SIGNATURE_LEN]) -> bool {
    ml_dsa_verify(&ml_dsa_decode_key(), sig)
}

fn ml_dsa_verify(key: &VerifyingKey<MlDsa65>, sig: &[u8; SIGNATURE_LEN]) -> bool {
    Signature::<MlDsa65>::decode(black_box(sig).into())
        .is_some_and(|sig| key.verify_with_context(black_box(MSG), &[], &sig))
}

/// Prints the stack usage of `verify` with a valid and an invalid signature.
fn row(name: &str, verify: impl Fn(&[u8; SIGNATURE_LEN]) -> bool, bad_sig: &[u8; SIGNATURE_LEN]) {
    let (valid, valid_bytes) = stack_usage(|| verify(SIG));
    let (invalid, invalid_bytes) = stack_usage(|| verify(bad_sig));
    assert!(valid && !invalid, "{name}");
    println!("  {name:<30} {valid_bytes:>7} {invalid_bytes:>7}");
}

#[entry]
fn main() -> ! {
    let mut bad_sig = *SIG;
    bad_sig[0] ^= 1;
    let (key, decode_bytes) = stack_usage(ml_dsa_decode_key);

    println!("ML-DSA-65 verification stack usage in bytes:");
    println!("  {:<30} {:>7} {:>7}", "", "valid", "invalid");
    row("mldsa-verify-otf", ours, &bad_sig);
    row("ml-dsa decode and verify", ml_dsa_decode_verify, &bad_sig);
    row(
        "ml-dsa verify, decoded key",
        |sig| ml_dsa_verify(&key, sig),
        &bad_sig,
    );
    println!();
    println!(
        "  {:<30} {decode_bytes:>7}",
        "ml-dsa key decode, without key"
    );
    println!(
        "  {:<30} {:>7}",
        "ml-dsa decoded key size",
        size_of::<VerifyingKey<MlDsa65>>()
    );
    process::exit(0)
}
