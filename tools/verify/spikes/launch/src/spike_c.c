// spike_c.c: see spike_c.h.
#include "spike_c.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <string.h>
#include <unistd.h>

// "BREV-SECRET-BODY" XOR 0x5A (same table as scan.c).
static const uint8_t MX[16] = {0x18, 0x08, 0x1f, 0x0c, 0x77, 0x09, 0x1f, 0x19,
                               0x08, 0x1f, 0x0e, 0x77, 0x18, 0x15, 0x1e, 0x03};

void spike_fill_marker(void *p, size_t n) {
    uint8_t *b = p;
    for (size_t i = 0; i < n; i++) b[i] = MX[i % 16] ^ 0x5A;
}

static uint8_t probe_buf[1 << 16];

size_t spike_probe(const void *p, size_t n, uint64_t *n55, uint64_t *nzero, uint64_t *nmarker) {
    if (n > sizeof probe_buf) n = sizeof probe_buf;
    mach_vm_size_t got = 0;
    *n55 = *nzero = *nmarker = 0;
    if (mach_vm_read_overwrite(mach_task_self(), (mach_vm_address_t)p, n, (mach_vm_address_t)probe_buf, &got) != KERN_SUCCESS)
        return 0;
    for (size_t i = 0; i < got; i++) {
        if (probe_buf[i] == 0x55) (*n55)++;
        if (probe_buf[i] == 0) (*nzero)++;
        if ((uint8_t)(probe_buf[i] ^ 0x5A) == MX[i % 16]) (*nmarker)++;
    }
    memset_s(probe_buf, sizeof probe_buf, 0, got);
    return (size_t)got;
}

int spike_cs_status(uint32_t *flags) {
    int (*csops)(pid_t, unsigned int, void *, size_t) = dlsym(RTLD_DEFAULT, "csops");
    if (!csops) return -2;
    return csops(getpid(), 0 /* CS_OPS_STATUS */, flags, sizeof *flags);
}

int spike_sandboxed(void) {
    int (*check)(pid_t, const char *, int, ...) = dlsym(RTLD_DEFAULT, "sandbox_check");
    if (!check) return -1;
    return check(getpid(), NULL, 0) ? 1 : 0;
}

int spike_try_open(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    close(fd);
    return 0;
}

int spike_execve(const char *path, char *const argv[], char *const envp[]) {
    execve(path, argv, envp);
    return errno;
}
