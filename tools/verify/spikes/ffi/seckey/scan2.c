#include "scan2.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <string.h>
#define CHUNK (1u << 20)
static uint8_t scratch[CHUNK + 64];
void scan2(const uint8_t nx[16], scan2_result *r) {
    memset(r, 0, sizeof *r);
    mach_vm_address_t addr = 0;
    uintptr_t s0 = (uintptr_t)scratch, s1 = s0 + sizeof scratch;
    for (;;) {
        mach_vm_size_t size = 0; natural_t depth = 64;
        vm_region_submap_info_data_64_t info; mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        if (mach_vm_region_recurse(mach_task_self(), &addr, &size, &depth, (vm_region_recurse_info_t)&info, &cnt) != KERN_SUCCESS) break;
        if (info.is_submap) { depth++; continue; }
        if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE)) {
            for (mach_vm_address_t a = addr; a < addr + size; a += CHUNK) {
                mach_vm_size_t len = (addr + size - a) < CHUNK ? (addr + size - a) : CHUNK;
                mach_vm_size_t rd = (a + len + 64 <= addr + size) ? len + 64 : len;
                if (a < s1 && a + rd > s0) continue;
                mach_vm_size_t got = 0;
                if (mach_vm_read_overwrite(mach_task_self(), a, rd, (mach_vm_address_t)scratch, &got) != KERN_SUCCESS) continue;
                for (size_t i = 0; i < len && i + 16 <= got; i++) {
                    if ((uint8_t)(scratch[i] ^ 0x5A) != nx[0]) continue;
                    size_t j = 1;
                    while (j < 16 && (uint8_t)(scratch[i + j] ^ 0x5A) == nx[j]) j++;
                    if (j == 16) { r->hits++; r->by_tag[info.user_tag & 255]++; }
                }
                memset_s(scratch, sizeof scratch, 0, got);
            }
        }
        addr += size;
    }
}
__attribute__((noinline)) void scrub_stack_c(unsigned kib) {
    unsigned char buf[64 * 1024];
    size_t n = (size_t)kib * 1024; if (n > sizeof buf) n = sizeof buf;
    memset_s(buf + sizeof buf - n, n, 0, n);
    __asm__ volatile("" : : "r"(buf) : "memory");
}
