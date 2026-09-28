#!/bin/bash
# FFI spike, step that needs a human: measure what Security.framework leaves in
# memory when a Touch ID-gated Secure Enclave key unwraps the DEK (ECIES) or
# does ECDH. The agent ran the same probe with a NON-biometric Secure Enclave key
# (no prompt possible); this repeats it with .biometryCurrentSet, as Brev will.
#
# What you will see: two Touch ID sheets, one per run (the requesting process
# is "probe" in Terminal). Touch the sensor each time. Cancelling is harmless:
# the run prints "unwrap failed" / "ECDH failed" and exits.
# Nothing is stored: both keys are ephemeral (kSecAttrIsPermanent = false), so
# no keychain item is created or left behind.
#
# Expected output (same shape as the agent's non-biometric runs):
#   ecies_bio: ... live after unwrap [A=1{2:1} B=1{2:1}] | after wiping returned CFData [A=0{} B=0{}]
#   ecdh_bio:  ... after wiping returned CFData [A=1{30:1} ...] | after 16 KiB stack scrub [A=1{30:1} ...] | after 64 KiB [A=0{} B=0{}]
# A=/B= count copies of the first/second 16 bytes of the secret; {tag:count}
# is the VM region tag (2 = malloc small, 7 = malloc tiny, 30 = thread stack).
# Please paste both output lines back to Claude.
set -euo pipefail
cd "$(dirname "$0")/seckey"
clang -O2 -c scan2.c -o scan2.o
swiftc -O -swift-version 5 -import-objc-header scan2.h probe.swift scan2.o -o probe
BREV_ALLOW_TOUCH_ID=1 ./probe ecies_bio
BREV_ALLOW_TOUCH_ID=1 ./probe ecdh_bio
