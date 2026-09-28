#include "scan.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <string.h>

static const uint8_t MARKER_X[16] = {0x18, 0x08, 0x1f, 0x0c, 0x77, 0x09, 0x1f, 0x19,
                                     0x08, 0x1f, 0x0e, 0x77, 0x18, 0x15, 0x1e, 0x03};
#define KEY 0x5A

static uint16_t GLYPHS_X[64];
static size_t GLYPHS_N = 0;

void brev_scan_set_glyphs(const uint16_t *xored, size_t n) {
    if (n > 64) n = 64;
    memcpy(GLYPHS_X, xored, n * 2);
    GLYPHS_N = n;
}

// Scratch buffer: regions are copied here chunk by chunk with
// mach_vm_read_overwrite (which fails instead of faulting). Its own range is
// skipped and it is wiped after every chunk.
#define CHUNK (1u << 20)
static uint8_t scratch[CHUNK + 64];

static void scan_buf(const uint8_t *b, size_t n, size_t limit, brev_scan_result *r, unsigned tag) {
    for (size_t i = 0; i < limit && i + 16 <= n; i++) {
        if ((uint8_t)(b[i] ^ KEY) != MARKER_X[0]) continue;
        size_t j = 1;
        while (j < 16 && (uint8_t)(b[i + j] ^ KEY) == MARKER_X[j]) j++;
        if (j == 16) { r->utf8_hits++; r->by_tag[tag & 255]++; }
    }
    for (size_t i = 0; i < limit && i + 32 <= n; i++) {
        if ((uint8_t)(b[i] ^ KEY) != MARKER_X[0] || b[i + 1] != 0) continue;
        size_t j = 1;
        while (j < 16 && (uint8_t)(b[i + 2 * j] ^ KEY) == MARKER_X[j] && b[i + 2 * j + 1] == 0) j++;
        if (j == 16) { r->utf16_hits++; r->by_tag[tag & 255]++; }
    }
    if (GLYPHS_N >= 4) {
        size_t need = GLYPHS_N * 2;
        for (size_t i = 0; i < limit && i + need <= n; i++) {
            size_t j = 0;
            while (j < GLYPHS_N) {
                uint16_t g = (uint16_t)(b[i + 2 * j] | (b[i + 2 * j + 1] << 8));
                if ((uint16_t)(g ^ 0x5A5A) != GLYPHS_X[j]) break;
                j++;
            }
            if (j == GLYPHS_N) { r->glyph_hits++; r->by_tag[tag & 255]++; }
        }
    }
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
                // Keep a 64-byte overlap so matches across chunk edges are not lost.
                mach_vm_size_t rd = (a + len + 64 <= addr + size) ? len + 64 : len;
                if (a < s1 && a + rd > s0) continue;  // our own scratch buffer
                mach_vm_size_t got = 0;
                if (mach_vm_read_overwrite(mach_task_self(), a, rd, (mach_vm_address_t)scratch, &got) != KERN_SUCCESS)
                    continue;
                r->bytes += len;
                // Only count matches that start inside [a, a+len).
                scan_buf(scratch, got, len, r, info.user_tag);
                memset_s(scratch, sizeof scratch, 0, got);
            }
        }
        addr += size;
    }
}
