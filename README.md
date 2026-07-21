# unsafety_hook

A lightweight x86 (i686) function hooking library for Windows, written in Rust.

`unsafety_hook` installs inline, mid-function, and vtable hooks into a running
32-bit process. It generates trampolines so the original function can still be
called, suspends other threads while patching to avoid races, and restores every
patched byte automatically when a hook is dropped.

Built as the low-level foundation for a set of GTA:SA / SA:MP modding projects,
where it handles all runtime code patching.

## Features

- **Inline hooks** — overwrite a function's prologue with a jump to your detour,
  returning a trampoline pointer to invoke the original.
- **Mid-function hooks** — patch an arbitrary instruction boundary and receive the
  full captured CPU context (`UnsafetyHookContext`: general-purpose registers,
  `EFlags`, `eip`) in an `extern "C"` callback, letting you read and modify
  register state before execution resumes.
- **Vtable hooks** — swap a function pointer at a given index in a C++ vtable.
- **Thread-safe patching** — other threads are suspended (via a RAII guard) while
  memory is written, then resumed, avoiding races with code being executed.
- **RAII cleanup** — each hook restores the original bytes on `Drop`; a single
  `remove_all()` tears everything down.
- **Minimal footprint** — uses [`lde`](https://crates.io/crates/lde) purely as a
  length disassembler (only instruction lengths are needed to relocate a clean
  prologue into the trampoline), keeping the dependency surface small.
- Hand-rolled `CONTEXT_X86` / `FLOATING_SAVE_AREA` layout for precise control over
  thread context on `i686` targets.

## Platform

- **Architecture:** x86 / `i686-pc-windows-msvc` only.
- **OS:** Windows.

x64 support is intentionally out of scope for now (see the `TODO` in `lib.rs`).
The library targets 32-bit processes, which is all its use cases require.

## Usage

```rust
use unsafety_hook::x86::{UnsafetyHook, UnsafetyHookContext};

// Inline hook: returns a trampoline to call the original.
let original = unsafe {
    UnsafetyHook::inline(target as *mut (), my_detour as *mut ())
}?;

// Mid hook: inspect / modify CPU context at an instruction boundary.
extern "C" fn on_hit(ctx: &mut UnsafetyHookContext) {
    if ctx.eflags.contains(unsafety_hook::x86::EFlags::ZF) {
        ctx.eax = 0;
    }
}
unsafe { UnsafetyHook::mid(target as *mut (), on_hit) }?;

// Vtable hook: replace entry `index` in an object's vtable.
let original_entry = unsafe {
    UnsafetyHook::vtable(object_ptr, index, detour_ptr)
}?;

// Remove everything and restore original bytes.
unsafe { UnsafetyHook::remove_all() };
```

Every entry point is `unsafe` — see the per-method `# Safety` documentation in the
source for the invariants the caller must uphold (validity and lifetime of
`target`, detour signature compatibility, instruction-boundary requirements for
mid hooks, and so on).

## Errors

Operations return `Result<_, UnsafetyHookError>`, covering invalid instructions at
the patch site, allocation/protection failures, encoding failures, and thread
suspension failures.

## Building

```sh
rustup target add i686-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc
```