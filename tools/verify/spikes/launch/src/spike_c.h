// spike_c.h: small C helpers for the launch spike (no marker is ever stored in clear).
#include <stddef.h>
#include <stdint.h>

// Fills p[0..n) with "BREV-SECRET-BODY" repeated (decoded on the fly from the XOR table).
void spike_fill_marker(void *p, size_t n);
// Reads up to n bytes at p with mach_vm_read_overwrite (no fault on freed or
// unmapped memory) and counts 0x55 bytes, zero bytes and bytes equal to the
// marker at that offset. Returns bytes read (0 if the read failed).
size_t spike_probe(const void *p, size_t n, uint64_t *n55, uint64_t *nzero, uint64_t *nmarker);
// csops(CS_OPS_STATUS) on this process, via dlsym. Returns 0 on success.
int spike_cs_status(uint32_t *flags);
// sandbox_check(getpid(), NULL, 0) via dlsym: 1 sandboxed, 0 not, -1 unknown.
int spike_sandboxed(void);
// open(path, O_RDONLY): returns 0 if it opened, else errno.
int spike_try_open(const char *path);
// execve(path, argv, envp); returns errno (only on failure).
int spike_execve(const char *path, char *const argv[], char *const envp[]);
