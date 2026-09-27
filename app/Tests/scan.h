// scan.h — counts copies of secrets in this process's own memory.
//
// Used by the Swift heap-scan harness (main.swift; docs/PHASE2_DESIGN.md
// §11) and, later, by the Verify build's self-scan. The needles are never
// materialised by the scanner: they are stored XORed, and memory is XORed
// before it is compared.
#include <stddef.h>
#include <stdint.h>

#define BREV_SCAN_NEEDLES 8

typedef struct {
    uint64_t utf8_hits;                       // "BREV-SECRET-BODY" as bytes (UTF-8)
    uint64_t utf16_hits;                      // the same marker as UTF-16LE
    uint64_t glyph_hits;                      // the glyph-id needle, if set
    uint64_t needle_hits[BREV_SCAN_NEEDLES];  // the byte needles, if set
    uint64_t regions;                         // readable+writable regions scanned
    uint64_t bytes;                           // bytes scanned
    uint64_t by_tag[256];                     // all hits per VM user_tag (malloc zones, stacks, ...)
} brev_scan_result;

// Scans every readable+writable region of this task.
void brev_scan(brev_scan_result *out);
// A sequence of 4 to 64 glyph ids, each XORed with 0x5A5A.
void brev_scan_set_glyphs(const uint16_t *xored, size_t n);
// Byte needle `index` (< BREV_SCAN_NEEDLES): 12 to 64 bytes, each XORed with
// 0x5A. Returns 0, or -1 for a bad index or length.
int brev_scan_set_needle(size_t index, const uint8_t *xored, size_t n);
