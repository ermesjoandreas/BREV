// 50 trials per size: how often is a freed block zeroed on this Mac?
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned char probe[1 << 20];
static int intact(uintptr_t addr, size_t n) {  // 1 intact, 0 zeroed, 2 other, 3 unmapped
    mach_vm_size_t got = 0;
    if (mach_vm_read_overwrite(mach_task_self(), addr, n, (mach_vm_address_t)probe, &got) != KERN_SUCCESS) return 3;
    size_t a5 = 0, z = 0;
    for (size_t i = 16; i < n; i++) { a5 += probe[i] == 0xA5; z += probe[i] == 0; }
    memset(probe, 0, n);
    return a5 == n - 16 ? 1 : z == n - 16 ? 0 : 2;
}
int main(void) {
    const size_t sizes[] = {16, 48, 512, 1024, 1025, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 131072, 524288};
    for (size_t k = 0; k < sizeof sizes / sizeof *sizes; k++) {
        size_t n = sizes[k]; int c[4] = {0};
        for (int t = 0; t < 50; t++) {
            void *keep = malloc(n);
            unsigned char *p = malloc(n); memset(p, 0xA5, n);
            uintptr_t a = (uintptr_t)p; free(p);
            c[intact(a, n)]++;
            free(keep);
        }
        printf("size %7zu: zeroed %2d  intact %2d  other %2d  unmapped %2d\n", n, c[0], c[1], c[2], c[3]);
    }
}
