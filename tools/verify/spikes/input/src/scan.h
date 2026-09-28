#include <stddef.h>
#include <stdint.h>

// Counts copies of the marker "BREV-SECRET-BODY" in every readable+writable
// region of this process. The marker is never materialised by the scanner:
// memory bytes are XORed with 0x5A and compared with the stored XOR form.
typedef struct {
    uint64_t utf8_hits;     // 16-byte marker as raw bytes / UTF-8
    uint64_t utf16_hits;    // marker as UTF-16LE (Core Text / NSString storage)
    uint64_t glyph_hits;    // optional glyph-id sequence (set with brev_scan_set_glyphs)
    uint64_t regions;       // regions scanned
    uint64_t bytes;         // bytes scanned
    uint64_t by_tag[256];   // utf8+utf16 hits per VM user_tag
} brev_scan_result;

void brev_scan(brev_scan_result *out);
// Optional: a sequence of 16-bit glyph ids (XOR 0x5A5A) to look for too.
void brev_scan_set_glyphs(const uint16_t *xored, size_t n);
