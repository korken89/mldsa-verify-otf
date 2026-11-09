//! Measures the peak stack usage and the executed instructions of ML-DSA verification here, and
//! of ML-DSA-65 verification in the `ml-dsa` crate, on a Cortex-M3 or M33.
//!
//! Each measurement fills the free stack with a pattern, runs the verification and finds the
//! lowest word that changed. The instruction count comes from the `icount.c` QEMU plugin and is
//! exact. Run with `make test-qemu`, which builds the plugin and starts QEMU.
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

/// Instructions executed so far, truncated to 32 bits.
#[inline(always)]
fn instructions() -> u32 {
    let n;
    // SAFETY: Moves r12 to itself. The plugin writes the instruction count into r12 first.
    unsafe { core::arch::asm!("mov r12, r12", out("r12") n, options(nostack, preserves_flags)) };
    n
}

/// Peak stack in bytes and executed instructions of one call.
struct Usage {
    stack: usize,
    instructions: u32,
}

/// Runs `f` and returns its result with its usage. Captures and the return value live in the
/// caller's frame, so they are not in the stack usage. The instructions include the call itself.
#[inline(never)]
fn measure<R>(f: impl FnOnce() -> R) -> (R, Usage) {
    let bottom = (&raw const _stack_end).cast_mut();
    let sp = cortex_m::register::msp::read() as *mut u32;
    // SAFETY: Everything from the end of the stack up to the stack pointer is unused.
    let free = unsafe { sp.offset_from(bottom) } as usize;
    for i in 0..free {
        // SAFETY: In bounds of the unused stack, see above.
        unsafe { bottom.add(i).write_volatile(PAINT) };
    }
    let start = instructions();
    let result = call(f);
    let instructions = instructions().wrapping_sub(start);
    // SAFETY: In bounds of the unused stack, see above.
    let untouched = (0..free)
        .find(|&i| unsafe { bottom.add(i).read_volatile() } != PAINT)
        .unwrap_or(free);
    assert!(untouched > 0, "stack overflow");
    let stack = (free - untouched) * 4;
    (
        result,
        Usage {
            stack,
            instructions,
        },
    )
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

/// Prints the usage of `verify` with a valid and an invalid signature, without the `overhead`
/// instructions of an empty call.
fn row<P: ParameterSet>(
    name: &str,
    v: &Vector<P>,
    overhead: u32,
    verify: impl Fn(&P::Signature) -> bool,
) where
    P::Signature: Copy + AsMut<[u8]>,
{
    let mut bad_sig = *v.sig;
    bad_sig.as_mut()[0] ^= 1;
    let (valid_ok, valid) = measure(|| verify(v.sig));
    let (invalid_ok, invalid) = measure(|| verify(&bad_sig));
    assert!(valid_ok && !invalid_ok, "{name}");
    println!(
        "  {name:<38} {:>7} {:>7} {:>9} {:>9}",
        valid.stack,
        invalid.stack,
        valid.instructions - overhead,
        invalid.instructions - overhead
    );
}

#[entry]
fn main() -> ! {
    let ((), empty) = measure(|| ());
    let overhead = empty.instructions;
    let (key, decode) = measure(ml_dsa_decode_key);

    println!(
        "ML-DSA verification on a {}, peak stack in bytes and instructions executed:",
        env!("CORE")
    );
    println!("  {:<38} {:>15} {:>19}", "", "stack", "instructions");
    println!(
        "  {:<38} {:>7} {:>7} {:>9} {:>9}",
        "", "valid", "invalid", "valid", "invalid"
    );
    row("mldsa-verify-otf, ML-DSA-44", &V44, overhead, |sig| {
        ours(&V44, sig)
    });
    row("mldsa-verify-otf, ML-DSA-65", &V65, overhead, |sig| {
        ours(&V65, sig)
    });
    row("mldsa-verify-otf, ML-DSA-87", &V87, overhead, |sig| {
        ours(&V87, sig)
    });
    row(
        "ml-dsa decode and verify, ML-DSA-65",
        &V65,
        overhead,
        ml_dsa_decode_verify,
    );
    row(
        "ml-dsa verify, decoded key, ML-DSA-65",
        &V65,
        overhead,
        |sig| ml_dsa_verify(&key, sig),
    );
    println!();
    println!(
        "  {:<38} {:>7} {:>17}",
        "ml-dsa key decode, without key",
        decode.stack,
        decode.instructions - overhead
    );
    println!(
        "  {:<38} {:>7}",
        "ml-dsa decoded key size",
        size_of::<VerifyingKey<ml_dsa::MlDsa65>>()
    );
    process::exit(0)
}
