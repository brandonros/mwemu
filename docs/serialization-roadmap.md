# Serialization Roadmap

Current status:

- Native `dump_to_file` / `load_from_file` remains the existing path for x86/x86_64, but still lacks dedicated roundtrip coverage.
- Minidump `dump_to_minidump` / `load_from_minidump` works for x86/x86_64.
- AArch64 native serialization plumbing is partially in place, but the ignored fixture roundtrip currently aborts with a stack overflow.
- AArch64 minidump import/export is still not implemented.

## Phase 1: Native Serialization Architecture Parity

- [x] Replace x86-only `SerializableThreadContext` payloads with architecture-aware variants.
- [x] Add AArch64 thread serialization for `RegsAarch64`, pre-op regs, and post-op regs.
- [x] Refactor `SerializableEmu` flattened current-thread state so it is not hard-wired to x86 registers/flags/FPU.
- [x] Refactor instruction/decode serialization so `ArchState::X86` and `ArchState::AArch64` can both be represented and restored.
- [x] Make `SerializableEmu::from(&Emu)` stop using x86-only accessors on AArch64.
- [x] Make `From<SerializableEmu> for Emu` restore AArch64 thread state and `arch_state` structurally.
- [ ] Investigate and fix the current stack overflow in `test_aarch64_native_serialization_fixture_roundtrip`.
- [ ] Replace the placeholder serialization smoke test with real native roundtrip coverage.
- [ ] Unignore `test_aarch64_native_serialization_fixture_roundtrip`.

## Phase 2: AArch64 Minidump Import

- [ ] Parse `MinidumpRawContext::Arm64` and `MinidumpRawContext::OldArm64`.
- [ ] Map ARM64 minidump register state into `RegsAarch64` (`x0..x30`, `sp`, `pc`, `nzcv`, FP/SIMD state).
- [ ] Build an AArch64 `SerializableEmu` from imported minidumps instead of routing through x86-shaped fields.
- [ ] Preserve AArch64 `cfg.arch`, OS, memory maps, modules, and current thread state on import.
- [ ] Treat ARM64 PE modules as 64-bit when reconstructing imported module metadata.
- [ ] Add an ARM64 minidump import fixture test.
- [ ] Unignore `test_aarch64_minidump_fixture_roundtrip` once import/export are ready.

## Phase 3: AArch64 Minidump Export

- [ ] Emit a valid `CONTEXT_ARM64` blob from `RegsAarch64`.
- [ ] Teach the minidump writer to export `ArchThreadState::AArch64`.
- [ ] Export ARM64 thread context, stack location, and relevant SIMD/FP register state.
- [ ] Validate ARM64 minidumps with the Rust `minidump` parser.
- [ ] Validate generated dumps with at least one external consumer such as Ghidra or WinDbg.

## Done Means

- [ ] Native serialization round-trips x86, x86_64, and AArch64 fixtures.
- [ ] Minidump import/export round-trips x86, x86_64, and AArch64 fixtures.
- [ ] The ignored AArch64 serialization/minidump tests are enabled and passing.
- [ ] The old x86-only "too complex" placeholder test is removed or replaced with real assertions.

## Finish Order

1. Stabilize native serialization first.
   Replace the placeholder smoke test with native x86/x86_64 roundtrip tests, then reproduce the current AArch64 stack overflow with the ignored fixture and reduce it to the smallest failing serialize/deserialize case.
2. Land native AArch64 roundtrip coverage.
   Fix the stack overflow, verify `Serialization::serialize` and `Serialization::deserialize` preserve AArch64 registers and `arch_state`, and then unignore the native AArch64 fixture test.
3. Implement ARM64 minidump import.
   Parse `MinidumpRawContext::Arm64` / `OldArm64`, map them into `RegsAarch64`, keep `cfg.arch`/OS/maps/modules intact, and add an import fixture test.
4. Implement ARM64 minidump export.
   Emit `CONTEXT_ARM64`, export `ArchThreadState::AArch64`, preserve stack and FP/SIMD state, and validate with the Rust `minidump` parser.
5. Do external validation and cleanup.
   Open generated ARM64 dumps in at least one real consumer such as Ghidra or WinDbg, enable the ignored minidump test, and only then call the feature complete.
