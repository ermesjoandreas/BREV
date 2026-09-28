# Phase 3 signature spike (sources)

The sources behind the first three rows of docs/PHASE3_DESIGN.md §0 (p256
verifies Security.framework signatures as produced, `Signature::from_der`
needs no DER code of ours, high-S), copied from the design's scratchpad
(`/private/tmp/claude-503/…/scratchpad/p3/`, which is volatile), and the four
vectors that brev-proto's tests commit. Sources only: `sigs.txt` (550 lines,
1.5 MB) and the binaries are not kept.

| File | What it does |
|---|---|
| `sigspike/main.swift` | Makes three non-permanent P-256 keys: a software `SecKey`, a Secure Enclave `SecKey` and a CryptoKit `SecureEnclave.P256` key, all with `[.privateKeyUsage]` only and an `LAContext` with `interactionNotAllowed`, so nothing can prompt and no keychain item is made. Signs random messages with `.ecdsaSignatureMessageX962SHA256` and with `.ecdsaSignatureDigestX962SHA256` over their SHA-256, and prints `kind variant pubhex msghex derhex` per signature |
| `derchk/` | For every line: `from_der`, verify with p256 0.14 as produced (high-S unchanged), the raw r ‖ s round trip, and a flipped message bit fails |
| `derchk-strict/` | For every line: `from_der` and the byte-for-byte DER re-encoding; then the six malformed DER inputs of §0 (it verifies after normalising S, which the final design does not need) |
| `pick-vectors.py` | Picks the four vectors from `sigs.txt` |
| `vectors.txt` | The four vectors, in `sigspike`'s line format, all digest variant with 366-byte messages: software key low-S (70-byte DER), software key high-S (72), Secure Enclave key high-S (72), Secure Enclave key with a 69-byte DER (31-byte s). `core/brev-proto/src/test_keys.rs` holds the same four as constants |

Rebuild and re-run (the spike used `200`, which gives 550 signatures):

```sh
xcrun swiftc -O sigspike/main.swift -o "$OUT/sigspike"
"$OUT/sigspike" 200 > "$OUT/sigs.txt"
(cd derchk && cargo run --release -- "$OUT/sigs.txt")
(cd derchk-strict && cargo run --release -- "$OUT/sigs.txt")
python3 pick-vectors.py "$OUT/sigs.txt" "$OUT/vectors.txt"
```

A new run makes new keys, so it gives other vectors than the committed ones.
Both checkers also run on `vectors.txt` itself: `derchk` prints
`as-produced verify ok 4 (high-S 2), raw round-trip ok 4, flipped-msg refused 4, digest-mode lines 4`
and `derchk-strict` prints `from_der ok 4, high-S 2, negatives refused 6/6`.
