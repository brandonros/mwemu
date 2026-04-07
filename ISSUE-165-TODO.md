# Issue #165 Restructure Todo

Tracking work for `restructure large files` on branch
`issue-165-restructure-large-files`.

## 1. `emu/execution.rs`

- [x] Extract shared run-loop startup, limit, loop-tracking, and trace helpers into `execution_control.rs`
- [x] Extract decode/cache-fill helpers out of `execution.rs`
- [x] Further separate single-threaded and multi-threaded runner concerns
- [x] Revisit REP-handling boundaries after the control-flow split

## 2. Linux syscall gateways

- [x] Convert `syscall32.rs` to descriptor-driven dispatch
- [x] Extract implemented `syscall32` handlers from the gateway
- [x] Convert `syscall64.rs` fallback name table to static metadata
- [x] Extract implemented `syscall64` handlers from the gateway

## 3. `arch/x86/regs.rs`

- [x] Macro-generate repetitive getter/setter helpers
- [x] Macro-generate repetitive show helpers
- [x] Preserve debugger/script register-name lookups while reducing duplication

## 4. `maps/mod.rs` + `maps/mem64.rs`

- [x] Extract shared scalar little-endian read/write helpers
- [x] Preserve `banzai` semantics
- [x] Preserve cross-map `write_bytes` behavior

## 5. `windows/structures/kernel64.rs`

- [x] Split the file into domain-oriented modules
- [x] Reassess macro/derive generation after the structural split

## 6. Loader/API paired cleanup

- [x] Share common readers between `loaders/pe/pe32.rs` and `loaders/pe/pe64.rs`
- [x] Extract common helper paths between `winapi32/ntdll.rs` and `winapi64/ntdll.rs`

## 7. Deferred unless they block feature work

- [x] Revisit `api/windows/winapi32/kernel32/mod.rs` and carry any remaining root-file cleanup into the later `kernel32` closeout sections below
- [x] Revisit `windows/constants.rs` and explicitly leave it alone for now unless feature work or code generation strategy changes

## 8. Follow-up consistency cleanup

- [x] Move the `emu/execution*` split into an `emu/execution/` module directory
- [x] Normalize `syscall32.rs` and `syscall64.rs` around one metadata/logging shape
- [x] Replace scalar helper string tags in `maps/mod.rs` and `maps/mem64.rs` with a typed enum
- [x] Run a focused review pass over the refactor diff before calling this polished

## 9. Linux syscall architectural follow-up

Section 2 and Section 8 got the syscall gateways into a more consistent state.
This section tracks the larger structural cleanup that is still open.

- [x] Split `syscall32.rs` into family-oriented modules behind a thin gateway (`fs`, `proc`, `net`, `memory`, `signal`, `misc`)
- [x] Split `syscall64.rs` into the same family-oriented module layout so 32-bit and 64-bit syscall code are organized the same way
- [x] Move fallback syscall-name/descriptor metadata out of the top-level gateway bodies so both 32-bit and 64-bit gateways now follow the same thin-dispatch shape
- [x] Normalize the remaining legacy per-branch syscall logging/tracing so implemented handlers and fallback paths share one format
- [x] Reassess which syscall helpers can actually be shared across 32-bit and 64-bit without hiding ABI differences (kept ABI-specific handlers separate in this pass)

## 10. WinAPI `kernel32` pair (`#128`)

Issue `#128` is about reducing duplication without hiding ABI adaptation.
This section tracks the `kernel32` pair specifically.

- [x] Extract shared API resolution, name lookup, and library-loading helpers from `winapi32/kernel32/mod.rs` and `winapi64/kernel32/mod.rs`
- [x] Keep 32-bit and 64-bit gateway / ABI adaptation thin and explicit
- [x] Reduce the size of both `kernel32` gateway files without growing a generic `common` dumping ground

## 11. WinAPI `ntdll` pair (`#128`)

This section should prefer domain-oriented helpers over growing `api/windows/common/ntdll.rs`.

- [x] Split `winapi32/ntdll.rs` into domain-oriented helpers (`heap`, `file`, `memory`, `loader`, `string`, `sync`, `misc`) behind a thin gateway
- [x] Split `winapi64/ntdll.rs` into the same domain-oriented layout
- [x] Keep `api/windows/common/ntdll.rs` small and limited to obviously shared semantics
- [x] Reassess which `ntdll` helpers can actually be shared across 32-bit and 64-bit without hiding ABI differences

## 12. `maps/mod.rs`

- [x] Separate map registry / indexing / allocation concerns from string, memcpy, and memset utility helpers
- [x] Preserve `banzai`, cross-map writes, and the typed scalar helper boundary
- [x] Reassess which helpers belong in `Maps` versus `Mem64`
- Boundary decision: keep cross-map orchestration in `Maps` (map lookup, cross-boundary writes/reads, search/inspection helpers) and keep single-region primitives in `Mem64` (contiguous scalar/string read-write implementation).

## 13. `emu/loaders.rs`

- [x] Separate PE32, PE64, ELF64, and Mach-O loader flows from generic `load_code` orchestration
- [x] Extract per-format base-selection and mapping helpers into format-oriented modules
- [x] Preserve current loader behavior, entry-point setup, and library mapping semantics
- Integrated validation: `nix develop` + `cargo check -p libmwemu --target x86_64-apple-darwin` passes on the combined Sections 9-13 tree.

## Remaining-wave subagent instructions

Use these rules for every remaining numbered section below.

- Give one subagent one numbered section end-to-end. Do not split one section across multiple workers unless we intentionally break that section apart first.
- The section owner updates only its own checkbox list and notes in this file.
- Stay inside the declared file set for the section unless a tiny integration touch is required elsewhere.
- Prefer structural splits, thinner root files, and clearer module boundaries over clever abstraction.
- Keep ABI adaptation explicit. Share semantic logic only where behavior is truly the same.
- Use `nix develop`.
- On Apple Silicon, validate with `--target x86_64-apple-darwin`.
- Preferred worker validation: `cargo check -p libmwemu --target x86_64-apple-darwin`.
- Preferred integrator validation before calling a wave done: `cargo test --target x86_64-apple-darwin`.
- Do not run `cargo fmt --all`.
- Progress visibility rule: boxes flip only after a worker returns and I review/integrate the result; active work is tracked with `In-progress note` lines under each section.

## 14. Linux syscall logging and tracing normalization

This is the one explicitly open item from the current syscall wave.

- [x] Introduce one per-ABI trace/log helper shape for the remaining legacy fallback paths so `syscall32` and `syscall64` each have a consistent internal format without pretending their calling conventions are identical
- [x] Replace the large remaining ad-hoc `log::trace!` arms in `syscall32/misc.rs` with helper-driven formatting so legacy fallback entries use the same prefix, syscall-name style, spacing, and argument-label style as implemented handlers
- [x] Do the same cleanup in `syscall64/misc.rs`, keeping argument extraction ABI-correct while making the visible trace format match the 32-bit side at the presentation level
- [x] Normalize name/style drift such as `fork` vs `fork()`, empty trailing placeholders, and inconsistent `fd/buf/sz` label wording without changing syscall behavior
- [x] Keep behavior-changing handlers behavior-only: if a branch currently stops the emulator, sets a return value, or touches memory, the cleanup here should only reroute logging/trace formatting around that logic
- [x] Keep 32-bit and 64-bit parameter formatting ABI-correct rather than forcing a misleading shared register-format helper
- [x] Preserve the current family-oriented module layout and thin gateway shape; this section is about consistency, not another structural rewrite
- [x] Avoid changing syscall semantics while normalizing traces
- Worker ownership: `crates/libmwemu/src/syscall/linux/syscall32.rs`, `crates/libmwemu/src/syscall/linux/syscall32/`, `crates/libmwemu/src/syscall/linux/syscall64.rs`, `crates/libmwemu/src/syscall/linux/syscall64/`
- Worker result: completed; Section 14 now uses per-ABI helper-driven syscall trace formatting in `syscall32/misc.rs` and `syscall64/misc.rs`, normalizes leftover naming/style drift in the legacy fallback paths, and leaves only auxiliary status/error logs as direct `log::trace!` calls. `nix develop` + `cargo check -p libmwemu --target x86_64-apple-darwin` passed.

## 15. Linux syscall root files: final thin-gateway pass

- [x] Move any remaining obvious concrete handler bodies out of top-level `syscall32.rs` and `syscall64.rs` into family modules where the concern boundary is clear
- [x] Leave the root files as gateway entrypoints, shared macros/helpers, and minimal legacy dispatch glue only
- [x] Keep 32-bit and 64-bit organization mirrored even when the actual handler bodies differ
- [x] Do not force cross-ABI sharing just to reduce line count
- Worker ownership: `crates/libmwemu/src/syscall/linux/syscall32.rs`, `crates/libmwemu/src/syscall/linux/syscall32/`, `crates/libmwemu/src/syscall/linux/syscall64.rs`, `crates/libmwemu/src/syscall/linux/syscall64/`
- Worker result: completed; root syscall files are now thin gateways and `nix develop` + `cargo check -p libmwemu --target x86_64-apple-darwin` passed.

## 16. WinAPI `kernel32` pair: final root-file thin-down (`#128`)

- [x] Reduce `winapi32/kernel32/mod.rs` and `winapi64/kernel32/mod.rs` toward module registry plus gateway responsibilities only
- [x] Move any remaining resolver, loader, IAT, or name-lookup helpers out of the root files into focused modules
- [x] Keep 32-bit and 64-bit ABI adaptation explicit
- [x] If more shared logic is clearly safe, prefer small helpers under `api/windows/common/kernel32.rs` or pair-local helpers, not a new generic dumping ground
- [x] Replace the still-massive flat `mod.rs` layout with a folder-backed structure so the root `kernel32` files stop being giant registries of hundreds of sibling modules
- [x] Group the extracted modules by concern in a way that makes navigation obvious, for example loader/resolver, process/thread, file/path, memory, registry, locale/string, and synchronization buckets
- [x] Leave the root `winapi32/kernel32/mod.rs` and `winapi64/kernel32/mod.rs` files as short hubs: module declarations, gateway dispatch, and only tiny glue/helpers that genuinely belong at the root
- [x] Mirror the concern layout across 32-bit and 64-bit sides so issue `#128` stays visible as “thin ABI wrappers around parallel semantic buckets,” not two unrelated trees
- [x] Do not satisfy this by stuffing more into `common/kernel32.rs`; the remaining work here is primarily structural organization of the pair-local trees
- Worker ownership: `crates/libmwemu/src/api/windows/common/kernel32.rs`, `crates/libmwemu/src/api/windows/winapi32/kernel32/`, `crates/libmwemu/src/api/windows/winapi64/kernel32/`
- Worker result: completed; mirrored folder-backed concern buckets landed under both `winapi32/kernel32/` and `winapi64/kernel32/`, the root `mod.rs` files are now hub-plus-gateway only, and `nix develop` + `cargo check -p libmwemu --target x86_64-apple-darwin` passed.

## 17. WinAPI `ntdll` pair: final root-file thin-down (`#128`)

- [x] Move any remaining obvious concrete handlers out of the root `winapi32/ntdll.rs` and `winapi64/ntdll.rs` files into the existing domain modules
- [x] Keep `api/windows/common/ntdll.rs` intentionally small; only obviously shared semantics belong there
- [x] Preserve the current domain split (`heap`, `file`, `memory`, `loader`, `string`, `sync`, `misc`) and keep ABI wrappers explicit
- [x] If the root files remain large after handler moves, prefer a cleaner `ntdll/mod.rs` hub shape over adding more logic to the root files
- Worker ownership: `crates/libmwemu/src/api/windows/common/ntdll.rs`, `crates/libmwemu/src/api/windows/winapi32/ntdll.rs`, `crates/libmwemu/src/api/windows/winapi32/ntdll/`, `crates/libmwemu/src/api/windows/winapi64/ntdll.rs`, `crates/libmwemu/src/api/windows/winapi64/ntdll/`
- Worker result: completed; `nix develop` + `cargo check -p libmwemu --target x86_64-apple-darwin` passed.

## 18. PE loader structural split / folderization pass

- [x] Move `pe32.rs` and `pe64.rs` toward a clearer folder-backed layout if that gives us better concern boundaries
- [x] Move the large PE32 structure/type definitions out of `pe32.rs` into dedicated submodules so the root file no longer mixes type declarations with parser/load orchestration
- [x] Do the same for PE64 where the root file still mixes width-specific structures with loader/parser logic
- [x] Split parser/load orchestration from data-model definitions so `pe32.rs` and `pe64.rs` become small hub files plus high-level entry types, not giant mixed “everything PE” roots
- [x] Keep `binding`, `resource`, and `relocation` helpers in their own modules and continue the split with parser-oriented modules rather than letting new parsing helpers accumulate back into the roots
- [x] Reassess which PE helpers or structures can truly be shared between 32-bit and 64-bit after the structural split; do not merge layouts that differ by field width or representation
- [x] Keep parser behavior stable; do not mix a structural split with a broad semantic rewrite in the same pass
- [x] Share 32-bit and 64-bit code only where the representation and behavior are genuinely the same
- Worker ownership: `crates/libmwemu/src/loaders/pe/pe32.rs`, `crates/libmwemu/src/loaders/pe/pe64.rs`, plus any new `crates/libmwemu/src/loaders/pe/*` structural files needed for the split
- Worker result: completed; common identical-layout PE model types moved to `loaders/pe/shared.rs`, width-specific PE32/PE64 headers moved into `pe32/types.rs` and `pe64/types.rs`, and parser/load orchestration moved into `pe32/parser.rs` and `pe64/parser.rs` so the root files are now small hubs plus exported entry types. `nix develop` + `cargo check -p libmwemu --target x86_64-apple-darwin` passed.

## 19. `windows/peb/peb64.rs` structural split

- [x] Separate bootstrap and init helpers from dynamic loader-list maintenance and rebuild helpers
- [x] Keep PEB/TEB creation behavior stable
- [x] Keep dynamic module link/unlink, hash-table rebuild, and loader-global maintenance behavior stable
- [x] Prefer folder-backed organization if that gives clearer boundaries than another very long flat file
- Worker ownership: `crates/libmwemu/src/windows/peb/peb64.rs` and any new `crates/libmwemu/src/windows/peb/*` structural files created by the split
- Worker result: completed; folder-backed `peb64/` layout landed and `nix develop` + `cargo check -p libmwemu --target x86_64-apple-darwin` passed.

## 20. `debug/gdb/target.rs` arch separation pass

- [x] Split the x86_64, x86, and aarch64 GDB target implementations into separate files under a folder-backed layout
- [x] Keep shared XML generation and library-list helpers in a small shared helper module
- [x] Avoid behavior changes to register access, resume, step, or memory read/write semantics in the same pass
- [x] Prefer structural clarity over aggressive trait abstraction unless the shared surface becomes truly obvious
- Worker ownership: `crates/libmwemu/src/debug/gdb/target.rs` and any new `crates/libmwemu/src/debug/gdb/target/*` files created by the split
- Worker result: completed; folder-backed `debug/gdb/target/` layout landed and `nix develop` + `cargo check -p libmwemu --target x86_64-apple-darwin` passed.

## 21. `winapi32/wininet.rs` folderization pass

- [x] Move the file toward a folder-backed layout with concern-oriented modules
- [x] Group helpers by concern such as session open/connect, request creation, send/query, URL parsing, and handle teardown
- [x] Preserve current handle semantics and tracing behavior
- [x] Keep this pass structural first; avoid mixing in new wininet behavior unless a bug is directly uncovered
- Worker ownership: `crates/libmwemu/src/api/windows/winapi32/wininet.rs` and any new `crates/libmwemu/src/api/windows/winapi32/wininet/*` files created by the split
- Worker result: completed; folder-backed `wininet/` layout landed and `nix develop` + `cargo check -p libmwemu --target x86_64-apple-darwin` passed.

## 22. Explicitly leave alone for now

Do not assign subagents here unless feature work or new evidence changes the decision.

- [x] `crates/libmwemu/src/arch/x86/regs.rs` is large but coherent enough after the recent cleanup
- [x] `crates/libmwemu/src/arch/x86/flags.rs` is high-risk and low-payoff for more structure work right now
- [x] `crates/libmwemu/src/windows/constants.rs` is mostly declarative data and does not need a restructure pass for this issue
- [x] `crates/libmwemu/src/maps/mem64.rs` should remain the single-region primitive owner for now
- [x] `crates/libmwemu/src/emu/operands.rs` is dense but focused and does not need a restructure pass right now
- [x] `crates/libmwemu/src/emu/execution/mod.rs` is already the intended execution hub after the earlier split
- [x] `crates/libmwemu/src/debug/console.rs` stays as-is unless command families start expanding again
- [x] `crates/libmwemu/src/debug/script.rs` stays as-is unless the script language surface grows enough to justify command modules
- [x] `crates/libmwemu/src/emu/object_handle/hive_parser.rs` stays as a cohesive parser/cache/test unit
- [x] `crates/pymwemu/src/lib.rs` stays as-is unless we later change how bindings are generated or organized

## 23. Issue #165 close-out checklist

- [x] Finish the formerly open concrete work in Sections 14, 16, and 18; no narrower follow-up issue was needed for this pass
- [x] Rerun the largest non-test `.rs` file report and confirm the remaining top files are either consciously deferred (`regs.rs`, `flags.rs`, `constants.rs`, `console.rs`, `script.rs`, `mem64.rs`) or now acceptable family/root files after this restructure wave (`syscall32/misc.rs`, `syscall64/misc.rs`, `winapi32/kernel32/mod.rs`)
- [x] Rerun `nix develop` + `cargo test --target x86_64-apple-darwin` on the combined tree
- [x] Post a final issue comment summarizing what was completed here versus what was intentionally deferred (`issuecomment-4201878954`)
- [ ] Close Issue #165 if the remaining work has either landed or been split into narrower follow-up issues
