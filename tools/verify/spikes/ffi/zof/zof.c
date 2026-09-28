// Does free()/realloc() on this Mac zero the freed block?
// Fills a block with 0xA5, frees it, then reads the old address back with
// mach_vm_read_overwrite (which fails instead of crashing if the page is gone).
// Reports, per size: "zeroed", "INTACT" (all 0xA5 bytes still there except
// possibly the first 16, which the allocator may reuse for free-list links),
// "partial", or "unmapped".
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *classify(uintptr_t addr, size_t n) {
    static unsigned char probe[4 << 20];
    mach_vm_size_t got = 0;
    kern_return_t kr = mach_vm_read_overwrite(mach_task_self(), addr, n,
                                              (mach_vm_address_t)probe, &got);
    if (kr != KERN_SUCCESS) return "unmapped";
    size_t a5 = 0, zero = 0;
    for (size_t i = 16; i < n; i++) {  // skip first 16 (free-list metadata)
        if (probe[i] == 0xA5) a5++;
        else if (probe[i] == 0) zero++;
    }
    memset(probe, 0, n);
    size_t body = n - 16;
    if (zero == body) return "zeroed";
    if (a5 == body) return "INTACT";
    static char buf[64];
    snprintf(buf, sizeof buf, "partial(a5=%zu zero=%zu of %zu)", a5, zero, body);
    return buf;
}

int main(void) {
    const size_t sizes[] = {32, 64, 256, 1008, 1024, 4096, 8192, 16384, 32768,
                            65536, 131072, 262144, 1048576};
    printf("MallocZeroOnFree=%s\n", getenv("MallocZeroOnFree") ? getenv("MallocZeroOnFree") : "(unset)");
    for (size_t k = 0; k < sizeof sizes / sizeof *sizes; k++) {
        size_t n = sizes[k];
        // keep a live neighbour so the freed block's region stays mapped
        void *keep = malloc(n);
        unsigned char *p = malloc(n);
        memset(p, 0xA5, n);
        uintptr_t addr = (uintptr_t)p;
        free(p);
        const char *after_free = classify(addr, n);

        // realloc growth: old block is freed by realloc when it moves
        unsigned char *q = malloc(n);
        memset(q, 0xA5, n);
        uintptr_t old = (uintptr_t)q;
        void *keep2 = malloc(64);  // discourage in-place growth
        unsigned char *r = realloc(q, n * 4);
        const char *after_realloc = ((uintptr_t)r == old) ? "grew-in-place" : classify(old, n);
        printf("size %8zu  free: %-10s  realloc(old block): %s\n", n, after_free, after_realloc);
        free(r);
        free(keep);
        free(keep2);
    }
    return 0;
}
