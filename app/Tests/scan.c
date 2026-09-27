// scan.c — see scan.h. Reads this task's memory with mach_vm_read_overwrite,
// which fails instead of faulting, one chunk at a time into a static scratch
// buffer that is skipped by the scan and wiped after every chunk.
#include "scan.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <string.h>

// "BREV-SECRET-BODY" XOR 0x5A.
static const uint8_t MARKER_X[16] = {0x18, 0x08, 0x1f, 0x0c, 0x77, 0x09, 0x1f, 0x19,
                                     0x08, 0x1f, 0x0e, 0x77, 0x18, 0x15, 0x1e, 0x03};
#define KEY 0x5A
#define GLYPH_KEY 0x5A5A
#define MAX_NEEDLE 64

static uint16_t GLYPHS_X[MAX_NEEDLE / 2];
static size_t GLYPHS_N = 0;
static uint8_t NEEDLES_X[BREV_SCAN_NEEDLES][MAX_NEEDLE];
static size_t NEEDLES_N[BREV_SCAN_NEEDLES];

void brev_scan_set_glyphs(const uint16_t *xored, size_t n) {
    if (n < 4 || n > MAX_NEEDLE / 2) n = 0;
    memcpy(GLYPHS_X, xored, n * 2);
    GLYPHS_N = n;
}

int brev_scan_set_needle(size_t index, const uint8_t *xored, size_t n) {
    if (index >= BREV_SCAN_NEEDLES || n < 12 || n > MAX_NEEDLE) return -1;
    memcpy(NEEDLES_X[index], xored, n);
    NEEDLES_N[index] = n;
    return 0;
}

// Scratch buffer. A chunk is read with MAX_NEEDLE bytes of overlap, so a
// match that starts in the chunk and runs past its end is still found.
#define CHUNK (1u << 20)
static uint8_t scratch[CHUNK + MAX_NEEDLE];

// Counts matches that START in b[0, limit); b has n readable bytes.
static void scan_buf(const uint8_t *b, size_t n, size_t limit, brev_scan_result *r, unsigned tag) {
    uint64_t hits = 0;
    for (size_t i = 0; i < limit && i + 16 <= n; i++) {
        if ((uint8_t)(b[i] ^ KEY) != MARKER_X[0]) continue;
        size_t j = 1;
        while (j < 16 && (uint8_t)(b[i + j] ^ KEY) == MARKER_X[j]) j++;
        if (j == 16) { r->utf8_hits++; hits++; }
    }
    for (size_t i = 0; i < limit && i + 32 <= n; i++) {
        if ((uint8_t)(b[i] ^ KEY) != MARKER_X[0] || b[i + 1] != 0) continue;
        size_t j = 1;
        while (j < 16 && (uint8_t)(b[i + 2 * j] ^ KEY) == MARKER_X[j] && b[i + 2 * j + 1] == 0) j++;
        if (j == 16) { r->utf16_hits++; hits++; }
    }
    if (GLYPHS_N > 0) {
        for (size_t i = 0; i < limit && i + GLYPHS_N * 2 <= n; i++) {
            size_t j = 0;
            while (j < GLYPHS_N) {
                uint16_t g = (uint16_t)(b[i + 2 * j] | (b[i + 2 * j + 1] << 8));
                if ((uint16_t)(g ^ GLYPH_KEY) != GLYPHS_X[j]) break;
                j++;
            }
            if (j == GLYPHS_N) { r->glyph_hits++; hits++; }
        }
    }
    for (size_t k = 0; k < BREV_SCAN_NEEDLES; k++) {
        size_t len = NEEDLES_N[k];
        if (len == 0) continue;
        const uint8_t *x = NEEDLES_X[k];
        for (size_t i = 0; i < limit && i + len <= n; i++) {
            if ((uint8_t)(b[i] ^ KEY) != x[0]) continue;
            size_t j = 1;
            while (j < len && (uint8_t)(b[i + j] ^ KEY) == x[j]) j++;
            if (j == len) { r->needle_hits[k]++; hits++; }
        }
    }
    r->by_tag[tag & 255] += hits;
}

void brev_scan(brev_scan_result *r) {
    memset(r, 0, sizeof *r);
    mach_vm_address_t addr = 0;
    uintptr_t s0 = (uintptr_t)scratch, s1 = s0 + sizeof scratch;
    for (;;) {
        mach_vm_size_t size = 0;
        natural_t depth = 64;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        if (mach_vm_region_recurse(mach_task_self(), &addr, &size, &depth,
                                   (vm_region_recurse_info_t)&info, &cnt) != KERN_SUCCESS)
            break;
        if (info.is_submap) { depth++; continue; }
        int rw = (info.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE);
        if (rw) {
            r->regions++;
            for (mach_vm_address_t a = addr; a < addr + size; a += CHUNK) {
                mach_vm_size_t len = (addr + size - a) < CHUNK ? (addr + size - a) : CHUNK;
                mach_vm_size_t rd = (a + len + MAX_NEEDLE <= addr + size) ? len + MAX_NEEDLE : len;
                if (a < s1 && a + rd > s0) continue;  // our own scratch buffer
                mach_vm_size_t got = 0;
                if (mach_vm_read_overwrite(mach_task_self(), a, rd, (mach_vm_address_t)scratch, &got) != KERN_SUCCESS)
                    continue;
                r->bytes += len;
                scan_buf(scratch, got, len, r, info.user_tag);
                memset_s(scratch, sizeof scratch, 0, got);
            }
        }
        addr += size;
    }
}
