//
//  Brev-Bridging-Header.h
//  Brev
//
//  Swift <-> Rust FFI wiring (CLAUDE.md §3.1: all logic, storage and crypto live in
//  the Rust core; Swift only ever sees UniFFI's opaque surface, never raw keys).
//
//  This is UniFFI's "compiled inline" path. The generated Generated/BrevCore.swift
//  begins with
//
//      #if canImport(BrevCoreFFI)
//      import BrevCoreFFI
//      #endif
//
//  We deliberately do NOT build a BrevCoreFFI Clang module (the generated
//  BrevCoreFFI.modulemap is not part of the target), so canImport(BrevCoreFFI) is
//  false and the C declarations that BrevCore.swift needs — RustBuffer,
//  ForeignBytes, RustCallStatus and the uniffi_brev_core_* / ffi_brev_core_*
//  functions — enter the app module through this bridging header instead.
//
//  Resolution (see app/project.yml and docs/DECISIONS.md D-0003):
//    * the header is found via HEADER_SEARCH_PATHS = $(SRCROOT)/Generated;
//    * the symbols are resolved at link time from the Rust staticlib, which
//      OTHER_LDFLAGS names by path: $(SRCROOT)/../core/target/release/libbrev_core.a.
//      It is never linked with -lbrev_core, because that same directory also holds
//      the bindgen-only libbrev_core.dylib and ld64 would pick the dylib first.
//
//  Both generated files are produced by scripts/gen-bindings.sh and are gitignored.
//

#import "BrevCoreFFI.h"
